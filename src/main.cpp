#include <boost/asio.hpp>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
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
  uint32_t protocol_version = 0x20000000;
  json merged_mining_coins;
  std::vector<struct AuxChainConfig> merged_mining_chains;
};

struct AuxChainConfig {
  std::string name;
  std::string ticker;
  std::string rpc_url;
  std::string rpc_user;
  std::string rpc_password;
  std::string payout_script_hex;
  std::optional<std::string> payout_address;
};

class AuxRpcClient;

struct AuxChainState {
  AuxChainConfig config;
  std::unique_ptr<AuxRpcClient> rpc;
  std::string hash;
  std::string target;
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
  std::optional<json> aux_chains_data;
};

// Состояние отдельной сессии майнера.
struct MinerSessionState {
  std::string extranonce1;
  uint32_t difficulty = 1;
  bool subscribed = false;
  bool authorized = false;
};

std::atomic<bool> g_running{true};
std::atomic<uint64_t> g_shares_accepted{0};
std::atomic<uint64_t> g_shares_rejected{0};
std::atomic<uint64_t> g_blocks_found{0};
std::atomic<uint64_t> g_auxpow_submitted{0};
std::atomic<uint64_t> g_auxpow_accepted{0};

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

json default_merged_mining_coins() {
  return json::array(
      {json{{"rank", 1},
            {"name", "Fractal Bitcoin"},
            {"ticker", "FB"},
            {"description", "Главная новинка 2025–2026, позиционируется как решение для масштабирования Bitcoin."}},
       json{{"rank", 2},
            {"name", "Rootstock"},
            {"ticker", "RSK/RBTC"},
            {"description", "Наиболее стабильный источник дополнительного дохода; RBTC привязан 1:1 к BTC."}},
       json{{"rank", 3},
            {"name", "Syscoin"},
            {"ticker", "SYS"},
            {"description", "Активно развивается, использует двухуровневую архитектуру (NEVM)."}},
       json{{"rank", 4},
            {"name", "Namecoin"},
            {"ticker", "NMC"},
            {"description", "Первая сеть с merged mining, остаётся актуальной."}},
       json{{"rank", 5},
            {"name", "Elastos"},
            {"ticker", "ELA"},
            {"description", "Проект «интернет-ОС», также майнится вместе с BTC."}},
       json{{"rank", 6},
            {"name", "Hathor"},
            {"ticker", "HTR"},
            {"description", "Гибридная архитектура DAG + Blockchain, поддерживает параллельный майнинг с Bitcoin."}}});
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

std::vector<uint8_t> base58_decode(const std::string &input) {
  static const std::string kAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  std::vector<uint8_t> out;
  out.reserve(input.size());
  for (char ch : input) {
    auto pos = kAlphabet.find(ch);
    if (pos == std::string::npos) {
      throw std::runtime_error("Недопустимый символ Base58.");
    }
    int carry = static_cast<int>(pos);
    for (size_t i = 0; i < out.size(); ++i) {
      int value = static_cast<int>(out[i]) * 58 + carry;
      out[i] = static_cast<uint8_t>(value & 0xff);
      carry = value >> 8;
    }
    while (carry > 0) {
      out.push_back(static_cast<uint8_t>(carry & 0xff));
      carry >>= 8;
    }
  }
  for (char ch : input) {
    if (ch == '1') {
      out.push_back(0);
    } else {
      break;
    }
  }
  std::reverse(out.begin(), out.end());
  return out;
}

std::vector<uint8_t> base58check_decode(const std::string &input) {
  std::vector<uint8_t> data = base58_decode(input);
  if (data.size() < 5) {
    throw std::runtime_error("Base58Check слишком короткий.");
  }
  std::vector<uint8_t> payload(data.begin(), data.end() - 4);
  std::vector<uint8_t> checksum(data.end() - 4, data.end());
  auto hash = sha256d(payload);
  if (!std::equal(checksum.begin(), checksum.end(), hash.begin())) {
    throw std::runtime_error("Неверная контрольная сумма Base58Check.");
  }
  return payload;
}

uint32_t bech32_polymod(const std::vector<uint8_t> &values) {
  uint32_t chk = 1;
  for (uint8_t v : values) {
    uint8_t top = chk >> 25;
    chk = (chk & 0x1ffffff) << 5 ^ v;
    if (top & 1) chk ^= 0x3b6a57b2;
    if (top & 2) chk ^= 0x26508e6d;
    if (top & 4) chk ^= 0x1ea119fa;
    if (top & 8) chk ^= 0x3d4233dd;
    if (top & 16) chk ^= 0x2a1462b3;
  }
  return chk;
}

std::vector<uint8_t> bech32_hrp_expand(const std::string &hrp) {
  std::vector<uint8_t> out;
  out.reserve(hrp.size() * 2 + 1);
  for (char ch : hrp) {
    out.push_back(static_cast<uint8_t>(ch >> 5));
  }
  out.push_back(0);
  for (char ch : hrp) {
    out.push_back(static_cast<uint8_t>(ch & 0x1f));
  }
  return out;
}

std::vector<uint8_t> convert_bits(const std::vector<uint8_t> &in, int from_bits, int to_bits, bool pad) {
  int acc = 0;
  int bits = 0;
  int maxv = (1 << to_bits) - 1;
  std::vector<uint8_t> out;
  for (uint8_t value : in) {
    if ((value >> from_bits) != 0) {
      throw std::runtime_error("Некорректные данные при конвертации битов.");
    }
    acc = (acc << from_bits) | value;
    bits += from_bits;
    while (bits >= to_bits) {
      bits -= to_bits;
      out.push_back(static_cast<uint8_t>((acc >> bits) & maxv));
    }
  }
  if (pad) {
    if (bits > 0) {
      out.push_back(static_cast<uint8_t>((acc << (to_bits - bits)) & maxv));
    }
  } else if (bits >= from_bits || ((acc << (to_bits - bits)) & maxv)) {
    throw std::runtime_error("Некорректное заполнение при конвертации битов.");
  }
  return out;
}

struct Bech32DecodeResult {
  std::string hrp;
  std::vector<uint8_t> data;
};

Bech32DecodeResult bech32_decode(const std::string &address) {
  static const std::string kCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  bool has_lower = false;
  bool has_upper = false;
  for (char ch : address) {
    if (std::isalpha(static_cast<unsigned char>(ch))) {
      if (std::islower(static_cast<unsigned char>(ch))) {
        has_lower = true;
      } else if (std::isupper(static_cast<unsigned char>(ch))) {
        has_upper = true;
      }
    }
  }
  if (has_lower && has_upper) {
    throw std::runtime_error("Bech32 адрес не должен смешивать регистры.");
  }
  std::string normalized = address;
  std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                 [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
  auto pos = normalized.rfind('1');
  if (pos == std::string::npos || pos < 1 || pos + 7 > normalized.size()) {
    throw std::runtime_error("Неверный формат Bech32.");
  }
  std::string hrp = normalized.substr(0, pos);
  std::vector<uint8_t> values;
  values.reserve(normalized.size() - pos - 1);
  for (size_t i = pos + 1; i < normalized.size(); ++i) {
    char ch = normalized[i];
    auto idx = kCharset.find(ch);
    if (idx == std::string::npos) {
      throw std::runtime_error("Недопустимый символ Bech32.");
    }
    values.push_back(static_cast<uint8_t>(idx));
  }
  std::vector<uint8_t> expanded = bech32_hrp_expand(hrp);
  expanded.insert(expanded.end(), values.begin(), values.end());
  if (bech32_polymod(expanded) != 1) {
    throw std::runtime_error("Неверная контрольная сумма Bech32.");
  }
  if (values.size() < 6) {
    throw std::runtime_error("Bech32 слишком короткий.");
  }
  std::vector<uint8_t> data(values.begin(), values.end() - 6);
  return {hrp, data};
}

std::string script_from_address(const std::string &address) {
  if (address.rfind("bc1", 0) == 0 || address.rfind("tb1", 0) == 0 || address.rfind("bcrt1", 0) == 0) {
    Bech32DecodeResult decoded = bech32_decode(address);
    if (decoded.data.empty()) {
      throw std::runtime_error("Bech32 без версии witness.");
    }
    uint8_t version = decoded.data[0];
    std::vector<uint8_t> program = convert_bits(
        std::vector<uint8_t>(decoded.data.begin() + 1, decoded.data.end()), 5, 8, false);
    if (version > 16) {
      throw std::runtime_error("Неверная версия witness.");
    }
    std::vector<uint8_t> script;
    script.push_back(version == 0 ? 0x00 : static_cast<uint8_t>(0x50 + version));
    script.push_back(static_cast<uint8_t>(program.size()));
    script.insert(script.end(), program.begin(), program.end());
    return bytes_to_hex(script);
  }
  std::vector<uint8_t> payload = base58check_decode(address);
  if (payload.size() != 21) {
    throw std::runtime_error("Неверная длина Base58Check адреса.");
  }
  uint8_t version = payload[0];
  std::vector<uint8_t> hash(payload.begin() + 1, payload.end());
  if (version == 0x00 || version == 0x6f) { // P2PKH mainnet/testnet
    std::vector<uint8_t> script = {0x76, 0xa9, 0x14};
    script.insert(script.end(), hash.begin(), hash.end());
    script.push_back(0x88);
    script.push_back(0xac);
    return bytes_to_hex(script);
  }
  if (version == 0x05 || version == 0xc4) { // P2SH mainnet/testnet
    std::vector<uint8_t> script = {0xa9, 0x14};
    script.insert(script.end(), hash.begin(), hash.end());
    script.push_back(0x87);
    return bytes_to_hex(script);
  }
  throw std::runtime_error("Неизвестная версия адреса Base58.");
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

class CurlGlobalGuard {
 public:
  CurlGlobalGuard() {
    if (++ref_count_ == 1) {
      curl_global_init(CURL_GLOBAL_DEFAULT);
    }
  }

  ~CurlGlobalGuard() {
    if (--ref_count_ == 0) {
      curl_global_cleanup();
    }
  }

 private:
  static std::atomic<int> ref_count_;
};

std::atomic<int> CurlGlobalGuard::ref_count_{0};

// RPC-клиент для работы с Bitcoin Core через JSON-RPC.
class RpcClient {
 public:
  explicit RpcClient(const Config &config) : config_(config) {}

  json call(const std::string &method, const json &params) {
    CurlGlobalGuard guard;
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

// RPC-клиент для aux-цепочек merged mining.
class AuxRpcClient {
 public:
  AuxRpcClient(std::string url, std::string user, std::string password)
      : rpc_url_(std::move(url)), rpc_user_(std::move(user)), rpc_password_(std::move(password)) {}

  json call(const std::string &method, const json &params) {
    CurlGlobalGuard guard;
    CURL *curl = curl_easy_init();
    if (!curl) {
      throw std::runtime_error("Не удалось инициализировать CURL");
    }

    std::string response;
    std::string payload = json{{"jsonrpc", "1.0"}, {"id", "stratum"}, {"method", method}, {"params", params}}.dump();

    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "content-type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, rpc_url_.c_str());
    curl_easy_setopt(curl, CURLOPT_USERNAME, rpc_user_.c_str());
    curl_easy_setopt(curl, CURLOPT_PASSWORD, rpc_password_.c_str());
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
  std::string rpc_url_;
  std::string rpc_user_;
  std::string rpc_password_;
};

// Менеджер шаблонов работы (job). Обновляет данные из getblocktemplate.
class JobManager {
 public:
  JobManager(const Config &config, RpcClient &rpc)
      : config_(config), rpc_(rpc) {
    extranonce1_ = random_hex(config_.extranonce1_size);
    for (const auto &chain : config_.merged_mining_chains) {
      AuxChainState state;
      state.config = chain;
      state.rpc = std::make_unique<AuxRpcClient>(chain.rpc_url, chain.rpc_user, chain.rpc_password);
      aux_chains_.push_back(std::move(state));
    }
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
    job.version = encode_little_endian(config_.protocol_version, 4);
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

    update_aux_chains();
    json aux_payload = build_aux_chains_payload();
    if (!aux_payload.empty()) {
      job.aux_chains_data = aux_payload;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    current_job_ = job;
  }

  bool submit_auxpow(const std::string &chain_id, const std::string &auxpow_hex) {
    g_auxpow_submitted.fetch_add(1);
    for (auto &chain : aux_chains_) {
      if (chain.config.name == chain_id || chain.config.ticker == chain_id) {
        if (chain.hash.empty()) {
          return false;
        }
        try {
          json params = json::array({chain.hash, auxpow_hex});
          auto result = chain.rpc->call("getauxblock", params);
          if (result.is_boolean()) {
            bool accepted = result.get<bool>();
            if (accepted) {
              g_auxpow_accepted.fetch_add(1);
              log_line("Auxpow принят для chain " + chain.config.name);
            }
            return accepted;
          }
          g_auxpow_accepted.fetch_add(1);
          log_line("Auxpow принят для chain " + chain.config.name);
          return true;
        } catch (const std::exception &ex) {
          log_line("Ошибка submit auxpow для " + chain.config.name + ": " + ex.what());
          return false;
        }
      }
    }
    return false;
  }

  JobTemplate current_job() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_job_.value();
  }

  std::string extranonce1() const { return extranonce1_; }

 private:
  void update_aux_chains() {
    for (auto &chain : aux_chains_) {
      try {
        auto result = chain.rpc->call("getauxblock", json::array());
        if (result.contains("hash")) {
          chain.hash = result["hash"].get<std::string>();
        }
        if (result.contains("target")) {
          chain.target = result["target"].get<std::string>();
        }
      } catch (const std::exception &ex) {
        log_line("Ошибка обновления aux chain " + chain.config.name + ": " + ex.what());
      }
    }
  }

  json build_aux_chains_payload() const {
    json payload = json::array();
    for (const auto &chain : aux_chains_) {
      if (chain.hash.empty() || chain.target.empty()) {
        continue;
      }
      payload.push_back({{"name", chain.config.name},
                         {"ticker", chain.config.ticker},
                         {"hash", chain.hash},
                         {"target", chain.target}});
    }
    return payload;
  }

  Config config_;
  RpcClient &rpc_;
  std::vector<AuxChainState> aux_chains_;
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
    } else if (method == "mining.get_merged_mining_coins") {
      handle_get_merged_mining_coins(request);
    } else if (method == "mining.get_merged_mining_chains") {
      handle_get_merged_mining_chains(request);
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

  // mining.get_merged_mining_coins: возвращаем список монет для merged mining.
  void handle_get_merged_mining_coins(const json &request) {
    json response = {{"id", request["id"]}, {"result", config_.merged_mining_coins}, {"error", nullptr}};
    send_json(response);
  }

  // mining.get_merged_mining_chains: возвращаем параметры aux-цепочек без секретов.
  void handle_get_merged_mining_chains(const json &request) {
    json chains = json::array();
    for (const auto &chain : config_.merged_mining_chains) {
      json entry = {{"name", chain.name}, {"ticker", chain.ticker}, {"payout_script_hex", chain.payout_script_hex}};
      if (chain.payout_address) {
        entry["payout_address"] = *chain.payout_address;
      }
      chains.push_back(entry);
    }
    json response = {{"id", request["id"]}, {"result", chains}, {"error", nullptr}};
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

    if (params.size() > 5 && params[5].is_array()) {
      for (const auto &item : params[5]) {
        if (!item.contains("name") || !item.contains("auxpow")) {
          continue;
        }
        std::string chain_id = item["name"].get<std::string>();
        std::string auxpow = item["auxpow"].get<std::string>();
        bool submitted = job_manager_.submit_auxpow(chain_id, auxpow);
        if (!submitted) {
          log_line("Auxpow не принят для chain " + chain_id);
        }
      }
    }

    if (accepted) {
      g_shares_accepted.fetch_add(1);
    } else {
      g_shares_rejected.fetch_add(1);
    }

    if (accepted && hash_meets_target(header_hash_hex, job.target)) {
      try {
        std::string block_hex = build_block_hex(header_hex, coinbase_tx, job.transactions_hex);
        rpc_submit_block(block_hex);
        g_blocks_found.fetch_add(1);
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
    json extra = json::object();
    if (job.aux_data) {
      extra["auxiliary"] = *job.aux_data;
    }
    if (job.aux_chains_data) {
      extra["aux_chains"] = *job.aux_chains_data;
    }
    if (!extra.empty()) {
      params.push_back(extra);
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
  if (data.contains("payout_script_hex")) {
    config.payout_script_hex = data.at("payout_script_hex").get<std::string>();
  } else if (data.contains("payout_address")) {
    config.payout_script_hex = script_from_address(data.at("payout_address").get<std::string>());
  } else {
    throw std::runtime_error("Нужно указать payout_script_hex или payout_address.");
  }
  config.extranonce1_size = data.value("extranonce1_size", 4);
  config.extranonce2_size = data.value("extranonce2_size", 8);
  config.enable_auxpow = data.value("enable_auxpow", true);
  config.protocol_version = data.value("protocol_version", 0x20000000);
  if (data.contains("merged_mining_coins")) {
    config.merged_mining_coins = data.at("merged_mining_coins");
  } else {
    config.merged_mining_coins = default_merged_mining_coins();
  }
  if (data.contains("merged_mining_chains")) {
    for (const auto &entry : data.at("merged_mining_chains")) {
      AuxChainConfig chain;
      chain.name = entry.at("name").get<std::string>();
      chain.ticker = entry.at("ticker").get<std::string>();
      chain.rpc_url = entry.at("rpc_url").get<std::string>();
      chain.rpc_user = entry.at("rpc_user").get<std::string>();
      chain.rpc_password = entry.at("rpc_password").get<std::string>();
      if (entry.contains("payout_script_hex")) {
        chain.payout_script_hex = entry.at("payout_script_hex").get<std::string>();
      } else if (entry.contains("payout_address")) {
        chain.payout_address = entry.at("payout_address").get<std::string>();
        chain.payout_script_hex = script_from_address(*chain.payout_address);
      } else {
        throw std::runtime_error("Нужно указать payout_script_hex или payout_address для merged_mining_chains.");
      }
      config.merged_mining_chains.push_back(std::move(chain));
    }
  }
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
      auto last_stats_log = std::chrono::steady_clock::now();
      while (g_running) {
        try {
          job_manager.update();
        } catch (const std::exception &ex) {
          log_line(std::string("Ошибка обновления шаблона: ") + ex.what());
        }
        auto now = std::chrono::steady_clock::now();
        if (now - last_stats_log >= std::chrono::seconds(30)) {
          last_stats_log = now;
          log_line("Статистика: shares accepted=" + std::to_string(g_shares_accepted.load()) +
                   ", rejected=" + std::to_string(g_shares_rejected.load()) +
                   ", blocks found=" + std::to_string(g_blocks_found.load()) +
                   ", auxpow submitted=" + std::to_string(g_auxpow_submitted.load()) +
                   ", auxpow accepted=" + std::to_string(g_auxpow_accepted.load()));
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
