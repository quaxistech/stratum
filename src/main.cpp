#include <boost/asio.hpp>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using json = nlohmann::json;
using boost::asio::ip::tcp;

namespace {

// Простой Stratum-сервер для работы с Bitcoin Core.
// Упрощённая версия: без учёта выплат/статистики,
// но с корректной сборкой заданий и отправкой блоков.

// Конфигурация сервиса. Значения загружаются из JSON.
struct Config {
  std::string rpc_url;
  std::string rpc_user;
  std::string rpc_password;
  std::string bind_address = "0.0.0.0";
  uint16_t port = 3333;
  uint32_t poll_interval_seconds = 5;
  uint32_t default_difficulty = 32;
  std::string payout_script_hex;
  size_t extranonce1_size = 4;
  size_t extranonce2_size = 8;
  bool enable_auxpow = true;
};

// Полный шаблон задания для майнеров Stratum.
struct JobTemplate {
  std::string job_id;
  std::string prevhash;
  std::string coinb1;
  std::string coinb2;
  std::vector<std::string> merkle_branches;
  std::string version;
  std::string nbits;
  std::string ntime;
  bool clean = true;
  std::string target;
  std::vector<std::string> transactions_hex;
  std::optional<json> aux_data;
};

// Состояние отдельной сессии майнера.
struct MinerSessionState {
  std::string extranonce1;
  uint32_t difficulty = 1;
  bool subscribed = false;
  bool authorized = false;
};

std::atomic<bool> g_running{true};

void log_line(const std::string &message) {
  auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  std::tm tm = *std::localtime(&now);
  std::ostringstream oss;
  oss << std::put_time(&tm, "%F %T") << " | " << message;
  std::cout << oss.str() << std::endl;
}

std::vector<uint8_t> hex_to_bytes(const std::string &hex) {
  std::vector<uint8_t> out;
  if (hex.size() % 2 != 0) {
    return out;
  }
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    uint8_t byte = static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16));
    out.push_back(byte);
  }
  return out;
}

std::string bytes_to_hex(const std::vector<uint8_t> &data) {
  std::ostringstream oss;
  for (uint8_t b : data) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
  }
  return oss.str();
}

std::string bytes_to_hex_rev(const std::vector<uint8_t> &data) {
  std::ostringstream oss;
  for (auto it = data.rbegin(); it != data.rend(); ++it) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*it);
  }
  return oss.str();
}

// Двойной SHA256 для расчёта хэшей блоков/транзакций.
std::vector<uint8_t> sha256d(const std::vector<uint8_t> &data) {
  std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, data.data(), data.size());
  SHA256_Final(hash.data(), &ctx);
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, hash.data(), hash.size());
  SHA256_Final(hash.data(), &ctx);
  return hash;
}

std::string random_hex(size_t bytes) {
  std::random_device rd;
  std::uniform_int_distribution<uint16_t> dist(0, 255);
  std::vector<uint8_t> data(bytes);
  for (auto &b : data) {
    b = static_cast<uint8_t>(dist(rd));
  }
  return bytes_to_hex(data);
}

// Кодирование VarInt в формате Bitcoin.
std::string encode_varint(uint64_t value) {
  std::vector<uint8_t> out;
  if (value < 0xfd) {
    out.push_back(static_cast<uint8_t>(value));
  } else if (value <= 0xffff) {
    out.push_back(0xfd);
    out.push_back(static_cast<uint8_t>(value & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
  } else if (value <= 0xffffffff) {
    out.push_back(0xfe);
    for (int i = 0; i < 4; ++i) {
      out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xff));
    }
  } else {
    out.push_back(0xff);
    for (int i = 0; i < 8; ++i) {
      out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xff));
    }
  }
  return bytes_to_hex(out);
}

// Запись числа в little-endian hex.
std::string encode_little_endian(uint64_t value, size_t bytes) {
  std::vector<uint8_t> out(bytes);
  for (size_t i = 0; i < bytes; ++i) {
    out[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xff);
  }
  return bytes_to_hex(out);
}

std::string hex_reverse(const std::string &hex) {
  auto bytes = hex_to_bytes(hex);
  std::reverse(bytes.begin(), bytes.end());
  return bytes_to_hex(bytes);
}

// Сборка coinbase-транзакции с extranonce и опциональным witness commitment.
std::string build_coinbase_hex(uint32_t height,
                               const std::string &coinbase_flags_hex,
                               const std::string &extranonce1,
                               const std::string &extranonce2,
                               const std::string &payout_script_hex,
                               uint64_t coinbase_value,
                               const std::optional<std::string> &witness_commitment_script) {
  std::string tx;
  tx += "01000000"; // version
  tx += "01";       // input count
  tx += std::string(64, '0'); // prevout hash
  tx += "ffffffff";           // prevout index

  std::string height_bytes;
  uint32_t tmp = height;
  while (tmp > 0) {
    height_bytes.push_back(static_cast<char>(tmp & 0xff));
    tmp >>= 8;
  }
  std::string height_push = bytes_to_hex(std::vector<uint8_t>(height_bytes.begin(), height_bytes.end()));
  std::string height_prefix = bytes_to_hex({static_cast<uint8_t>(height_bytes.size())});

  std::string script_sig = height_prefix + height_push + coinbase_flags_hex + extranonce1 + extranonce2;
  tx += encode_varint(script_sig.size() / 2);
  tx += script_sig;
  tx += "ffffffff"; // sequence

  uint64_t output_count = witness_commitment_script ? 2 : 1;
  tx += encode_varint(output_count);
  tx += encode_little_endian(coinbase_value, 8);
  tx += encode_varint(payout_script_hex.size() / 2);
  tx += payout_script_hex;
  if (witness_commitment_script) {
    tx += encode_little_endian(0, 8);
    tx += encode_varint(witness_commitment_script->size() / 2);
    tx += *witness_commitment_script;
  }
  tx += "00000000"; // locktime
  return tx;
}

// Формирование веток Merkle-дерева для coinbase.
std::vector<std::string> build_merkle_branches(const std::vector<std::string> &tx_hashes_hex) {
  std::vector<std::vector<uint8_t>> hashes;
  hashes.reserve(tx_hashes_hex.size());
  for (const auto &hex : tx_hashes_hex) {
    auto bytes = hex_to_bytes(hex);
    std::reverse(bytes.begin(), bytes.end());
    hashes.push_back(bytes);
  }

  std::vector<std::string> branches;
  size_t index = 0;
  while (hashes.size() > 1) {
    if (hashes.size() % 2 == 1) {
      hashes.push_back(hashes.back());
    }

    std::vector<std::vector<uint8_t>> next;
    for (size_t i = 0; i < hashes.size(); i += 2) {
      std::vector<uint8_t> concat = hashes[i];
      concat.insert(concat.end(), hashes[i + 1].begin(), hashes[i + 1].end());
      auto hash = sha256d(concat);
      next.push_back(hash);
    }

    if (index < hashes.size()) {
      size_t sibling_index = (index % 2 == 0) ? index + 1 : index - 1;
      if (sibling_index < hashes.size()) {
        branches.push_back(bytes_to_hex_rev(hashes[sibling_index]));
      }
    }

    index /= 2;
    hashes = std::move(next);
  }

  return branches;
}

// Пересчёт корня Merkle по coinbase и веткам.
std::string calculate_merkle_root(const std::string &coinbase_hash_hex,
                                  const std::vector<std::string> &branches_hex) {
  std::vector<uint8_t> current = hex_to_bytes(coinbase_hash_hex);
  std::reverse(current.begin(), current.end());
  for (const auto &branch : branches_hex) {
    auto branch_bytes = hex_to_bytes(branch);
    std::reverse(branch_bytes.begin(), branch_bytes.end());
    std::vector<uint8_t> concat = current;
    concat.insert(concat.end(), branch_bytes.begin(), branch_bytes.end());
    current = sha256d(concat);
  }
  std::reverse(current.begin(), current.end());
  return bytes_to_hex(current);
}

// Получение цели из nBits (как в заголовке блока).
std::string target_from_nbits(const std::string &nbits_hex) {
  if (nbits_hex.size() != 8) {
    return std::string(64, '0');
  }
  uint32_t nbits = std::stoul(nbits_hex, nullptr, 16);
  uint32_t exponent = nbits >> 24;
  uint32_t mantissa = nbits & 0x007fffff;
  std::vector<uint8_t> target(32, 0);
  size_t offset = exponent > 3 ? exponent - 3 : 0;
  if (offset + 3 <= target.size()) {
    target[offset] = static_cast<uint8_t>((mantissa >> 16) & 0xff);
    target[offset + 1] = static_cast<uint8_t>((mantissa >> 8) & 0xff);
    target[offset + 2] = static_cast<uint8_t>(mantissa & 0xff);
  }
  std::reverse(target.begin(), target.end());
  return bytes_to_hex(target);
}

// Пересчёт цели для доли (share) из сложности.
std::string target_from_difficulty(uint32_t difficulty) {
  const uint8_t diff1_target_bytes[32] = {
      0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  std::vector<uint8_t> target(diff1_target_bytes, diff1_target_bytes + 32);

  uint64_t carry = 0;
  for (int i = 31; i >= 0; --i) {
    uint64_t value = (static_cast<uint64_t>(target[i]) << 8) + carry;
    target[i] = static_cast<uint8_t>(value / difficulty);
    carry = value % difficulty;
  }
  return bytes_to_hex(target);
}

// Сравнение хэша и цели в виде hex-строк.
bool hash_meets_target(const std::string &hash_hex, const std::string &target_hex) {
  if (hash_hex.size() != target_hex.size()) {
    return false;
  }
  return hash_hex <= target_hex;
}

// Сборка полного блока: заголовок + список транзакций.
std::string build_block_hex(const std::string &header_hex,
                            const std::string &coinbase_hex,
                            const std::vector<std::string> &transactions_hex) {
  std::string block = header_hex;
  uint64_t tx_count = 1 + transactions_hex.size();
  block += encode_varint(tx_count);
  block += coinbase_hex;
  for (const auto &tx : transactions_hex) {
    block += tx;
  }
  return block;
}

size_t curl_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
  auto *response = static_cast<std::string *>(userdata);
  response->append(ptr, size * nmemb);
  return size * nmemb;
}

// RPC-клиент для работы с Bitcoin Core через JSON-RPC.
class RpcClient {
 public:
  explicit RpcClient(const Config &config) : config_(config) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
  }

  ~RpcClient() { curl_global_cleanup(); }

  json call(const std::string &method, const json &params) {
    CURL *curl = curl_easy_init();
    if (!curl) {
      throw std::runtime_error("Не удалось инициализировать CURL");
    }

    std::string response;
    std::string payload = json{{"jsonrpc", "1.0"}, {"id", "stratum"}, {"method", method}, {"params", params}}.dump();

    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "content-type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, config_.rpc_url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERNAME, config_.rpc_user.c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, config_.rpc_password.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
      throw std::runtime_error(std::string("Ошибка RPC: ") + curl_easy_strerror(res));
    }

    auto parsed = json::parse(response);
    if (!parsed["error"].is_null()) {
      throw std::runtime_error("RPC ошибка: " + parsed["error"].dump());
    }
    return parsed["result"];
  }

 private:
  Config config_;
};

// Менеджер шаблонов работы (job). Обновляет данные из getblocktemplate.
class JobManager {
 public:
  JobManager(const Config &config, RpcClient &rpc)
      : config_(config), rpc_(rpc) {
    extranonce1_ = random_hex(config_.extranonce1_size);
  }

  void update() {
    json rules = json::array({"segwit"});
    if (config_.enable_auxpow) {
      rules.push_back("auxpow");
    }
    json params = json::array();
    params.push_back({{"rules", rules}});
    auto result = rpc_.call("getblocktemplate", params);

    JobTemplate job;
    job.job_id = std::to_string(++job_counter_);
    job.prevhash = hex_reverse(result["previousblockhash"].get<std::string>());
    job.version = encode_little_endian(result["version"].get<uint32_t>(), 4);
    job.nbits = result["bits"].get<std::string>();
    job.ntime = encode_little_endian(result["curtime"].get<uint32_t>(), 4);
    job.clean = true;
    job.target = target_from_nbits(job.nbits);

    uint32_t height = result["height"].get<uint32_t>();
    std::string coinbase_flags = "";
    if (result.contains("coinbaseaux") && result["coinbaseaux"].contains("flags")) {
      coinbase_flags = result["coinbaseaux"]["flags"].get<std::string>();
    }

    std::optional<std::string> witness_commitment;
    if (result.contains("default_witness_commitment")) {
      witness_commitment = result["default_witness_commitment"].get<std::string>();
    }
    std::string coinbase_tx = build_coinbase_hex(
        height,
        coinbase_flags,
        extranonce1_,
        std::string(config_.extranonce2_size * 2, '0'),
        config_.payout_script_hex,
        result["coinbasevalue"].get<uint64_t>(),
        witness_commitment);

    size_t extranonce_pos = coinbase_tx.find(extranonce1_) + extranonce1_.size();
    job.coinb1 = coinbase_tx.substr(0, extranonce_pos);
    job.coinb2 = coinbase_tx.substr(extranonce_pos + config_.extranonce2_size * 2);

    std::vector<std::string> tx_hashes;
    tx_hashes.reserve(result["transactions"].size() + 1);
    auto coinbase_hash = sha256d(hex_to_bytes(coinbase_tx));
    tx_hashes.push_back(bytes_to_hex_rev(coinbase_hash));

    job.transactions_hex.clear();
    for (const auto &tx : result["transactions"]) {
      tx_hashes.push_back(tx["hash"].get<std::string>());
      if (tx.contains("data")) {
        job.transactions_hex.push_back(tx["data"].get<std::string>());
      }
    }

    job.merkle_branches = build_merkle_branches(tx_hashes);
    if (result.contains("auxiliary")) {
      job.aux_data = result["auxiliary"];
    }

    std::lock_guard<std::mutex> lock(mutex_);
    current_job_ = job;
  }

  JobTemplate current_job() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_job_.value();
  }

  std::string extranonce1() const { return extranonce1_; }

 private:
  Config config_;
  RpcClient &rpc_;
  std::string extranonce1_;
  mutable std::mutex mutex_;
  std::optional<JobTemplate> current_job_;
  uint64_t job_counter_ = 0;
};

// Сессия Stratum для конкретного майнера.
class StratumSession : public std::enable_shared_from_this<StratumSession> {
 public:
  StratumSession(tcp::socket socket, const Config &config, JobManager &job_manager)
      : socket_(std::move(socket)), config_(config), job_manager_(job_manager) {}

  void start() {
    state_.difficulty = config_.default_difficulty;
    do_read();
  }

 private:
  void do_read() {
    auto self = shared_from_this();
    boost::asio::async_read_until(socket_, buffer_, '\n',
                                 [this, self](boost::system::error_code ec, std::size_t length) {
      if (ec) {
        log_line("Клиент отключился: " + ec.message());
        return;
      }
      std::istream is(&buffer_);
      std::string line;
      std::getline(is, line);
      if (!line.empty()) {
        handle_message(line);
      }
      do_read();
    });
  }

  void send_json(const json &message) {
    auto serialized = message.dump() + "\n";
    auto self = shared_from_this();
    boost::asio::async_write(socket_, boost::asio::buffer(serialized),
                             [self](boost::system::error_code ec, std::size_t) {
      if (ec) {
        log_line("Ошибка отправки: " + ec.message());
      }
    });
  }

  // Обработка входящего JSON-RPC сообщения от майнера.
  void handle_message(const std::string &line) {
    json request;
    try {
      request = json::parse(line);
    } catch (const std::exception &ex) {
      log_line(std::string("Неверный JSON от майнера: ") + ex.what());
      return;
    }

    std::string method = request.value("method", "");
    if (method == "mining.subscribe") {
      handle_subscribe(request);
    } else if (method == "mining.authorize") {
      handle_authorize(request);
    } else if (method == "mining.submit") {
      handle_submit(request);
    } else {
      json response = {{"id", request["id"]}, {"result", nullptr}, {"error", "Неизвестный метод"}};
      send_json(response);
    }
  }

  // mining.subscribe: выдаём extranonce и настройки.
  void handle_subscribe(const json &request) {
    state_.extranonce1 = job_manager_.extranonce1();
    state_.subscribed = true;

    json response = {
        {"id", request["id"]},
        {"result", json::array({json::array({json::array({"mining.notify", "1"}), json::array({"mining.set_difficulty", "1"})}), state_.extranonce1, config_.extranonce2_size})},
        {"error", nullptr}};
    send_json(response);

    send_set_difficulty();
    send_notify(true);
  }

  // mining.authorize: упрощённая авторизация (без реальной проверки).
  void handle_authorize(const json &request) {
    state_.authorized = true;
    json response = {{"id", request["id"]}, {"result", true}, {"error", nullptr}};
    send_json(response);
  }

  // mining.submit: проверяем шар, при необходимости отправляем блок в сеть.
  void handle_submit(const json &request) {
    if (!state_.subscribed || !state_.authorized) {
      json response = {{"id", request["id"]}, {"result", false}, {"error", "Не подписан/не авторизован"}};
      send_json(response);
      return;
    }

    auto params = request["params"];
    if (params.size() < 5) {
      json response = {{"id", request["id"]}, {"result", false}, {"error", "Недостаточно параметров"}};
      send_json(response);
      return;
    }

    std::string job_id = params[1].get<std::string>();
    std::string extranonce2 = params[2].get<std::string>();
    std::string ntime = params[3].get<std::string>();
    std::string nonce = params[4].get<std::string>();

    auto job = job_manager_.current_job();
    if (job.job_id != job_id) {
      json response = {{"id", request["id"]}, {"result", false}, {"error", "Неактуальная работа"}};
      send_json(response);
      return;
    }

    std::string coinbase_tx = job.coinb1 + extranonce2 + job.coinb2;
    auto coinbase_hash = sha256d(hex_to_bytes(coinbase_tx));
    std::string coinbase_hash_hex = bytes_to_hex_rev(coinbase_hash);
    std::string merkle_root = calculate_merkle_root(coinbase_hash_hex, job.merkle_branches);

    std::string header_hex = job.version + job.prevhash + merkle_root + ntime + job.nbits + nonce;
    auto header_hash = sha256d(hex_to_bytes(header_hex));
    std::string header_hash_hex = bytes_to_hex_rev(header_hash);

    std::string share_target = target_from_difficulty(state_.difficulty);
    bool accepted = hash_meets_target(header_hash_hex, share_target);

    if (accepted && hash_meets_target(header_hash_hex, job.target)) {
      try {
        std::string block_hex = build_block_hex(header_hex, coinbase_tx, job.transactions_hex);
        rpc_submit_block(block_hex);
        log_line("Найден блок! Отправлен в сеть.");
      } catch (const std::exception &ex) {
        log_line(std::string("Ошибка submitblock: ") + ex.what());
      }
    }

    json response = {{"id", request["id"]}, {"result", accepted}, {"error", nullptr}};
    send_json(response);
  }

  // Установка сложности шар для майнера.
  void send_set_difficulty() {
    json notification = {{"id", nullptr}, {"method", "mining.set_difficulty"}, {"params", json::array({state_.difficulty})}};
    send_json(notification);
  }

  // Отправка нового задания. При наличии auxpow добавляем aux-данные в конец параметров.
  void send_notify(bool clean) {
    JobTemplate job = job_manager_.current_job();
    job.clean = clean;

    json params = json::array({job.job_id,
                               job.prevhash,
                               job.coinb1,
                               job.coinb2,
                               job.merkle_branches,
                               job.version,
                               job.nbits,
                               job.ntime,
                               job.clean});
    if (job.aux_data) {
      params.push_back(*job.aux_data);
    }
    json notification = {{"id", nullptr}, {"method", "mining.notify"}, {"params", params}};
    send_json(notification);
  }

  // Отправка найденного блока в Bitcoin Core.
  void rpc_submit_block(const std::string &block_hex) {
    static std::mutex rpc_mutex;
    std::lock_guard<std::mutex> lock(rpc_mutex);
    static RpcClient *rpc = nullptr;
    if (!rpc) {
      rpc = new RpcClient(config_);
    }
    json params = json::array({block_hex});
    rpc->call("submitblock", params);
  }

  tcp::socket socket_;
  boost::asio::streambuf buffer_;
  Config config_;
  JobManager &job_manager_;
  MinerSessionState state_;
};

// TCP-сервер, принимающий подключения майнеров.
class StratumServer {
 public:
  StratumServer(const Config &config, JobManager &job_manager)
      : config_(config), job_manager_(job_manager),
        acceptor_(io_context_, tcp::endpoint(boost::asio::ip::make_address(config.bind_address), config.port)) {}

  void run() {
    do_accept();
    io_context_.run();
  }

  void stop() { io_context_.stop(); }

 private:
  void do_accept() {
    acceptor_.async_accept([this](boost::system::error_code ec, tcp::socket socket) {
      if (!ec) {
        log_line("Новое подключение: " + socket.remote_endpoint().address().to_string());
        std::make_shared<StratumSession>(std::move(socket), config_, job_manager_)->start();
      }
      do_accept();
    });
  }

  Config config_;
  JobManager &job_manager_;
  boost::asio::io_context io_context_;
  tcp::acceptor acceptor_;
};

// Загрузка конфигурации из JSON-файла.
Config load_config(const std::string &path) {
  std::ifstream file(path);
  if (!file) {
    throw std::runtime_error("Не удалось открыть конфиг: " + path);
  }
  json data = json::parse(file);
  Config config;
  config.rpc_url = data.at("rpc_url").get<std::string>();
  config.rpc_user = data.at("rpc_user").get<std::string>();
  config.rpc_password = data.at("rpc_password").get<std::string>();
  config.bind_address = data.value("bind_address", "0.0.0.0");
  config.port = data.value("port", 3333);
  config.poll_interval_seconds = data.value("poll_interval_seconds", 5);
  config.default_difficulty = data.value("default_difficulty", 32);
  config.payout_script_hex = data.at("payout_script_hex").get<std::string>();
  config.extranonce1_size = data.value("extranonce1_size", 4);
  config.extranonce2_size = data.value("extranonce2_size", 8);
  config.enable_auxpow = data.value("enable_auxpow", true);
  return config;
}

// Обработчик сигналов для корректной остановки.
void signal_handler(int) {
  g_running = false;
}

} // namespace

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cerr << "Использование: stratum_server <config.json>" << std::endl;
    return 1;
  }

  std::signal(SIGINT, signal_handler);
  std::signal(SIGTERM, signal_handler);

  try {
    Config config = load_config(argv[1]);
    RpcClient rpc(config);
    JobManager job_manager(config, rpc);

    job_manager.update();

    std::thread poller([&]() {
      while (g_running) {
        try {
          job_manager.update();
        } catch (const std::exception &ex) {
          log_line(std::string("Ошибка обновления шаблона: ") + ex.what());
        }
        std::this_thread::sleep_for(std::chrono::seconds(config.poll_interval_seconds));
      }
    });

    StratumServer server(config, job_manager);
    server.run();
    poller.join();
  } catch (const std::exception &ex) {
    std::cerr << "Ошибка: " << ex.what() << std::endl;
    return 1;
  }

  return 0;
}
