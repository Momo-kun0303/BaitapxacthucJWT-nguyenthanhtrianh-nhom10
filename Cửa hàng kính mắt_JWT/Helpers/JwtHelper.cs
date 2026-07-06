using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Cửa_hàng_kính_mắt_JWT.Helpers
{
    public class JwtPayload
    {
        public string Name { get; set; }
        public string Role { get; set; }
        public long Exp { get; set; } // Thời gian hết hạn (Unix Timestamp)
    }

    public static class JwtHelper
    {
        // 1. Hàm tạo JWT thủ công
        public static string GenerateToken(string username, string role, string secretKey)
        {
            var header = new { alg = "HS256", typ = "JWT" };
            var exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
            var payload = new JwtPayload { Name = username, Role = role, Exp = exp };

            string headerBase64 = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));
            string payloadBase64 = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));

            string stringToSign = $"{headerBase64}.{payloadBase64}";
            string signature = CreateSignature(stringToSign, secretKey);

            return $"{stringToSign}.{signature}";
        }

        // 2. Hàm xác thực và lấy thông tin từ JWT
        public static JwtPayload ValidateToken(string token, string secretKey)
        {
            var parts = token.Split('.');
            if (parts.Length != 3) return null;

            var header = parts[0];
            var payload = parts[1];
            var signature = parts[2];

            // Kiểm tra chữ ký xem token có bị giả mạo không
            string expectedSignature = CreateSignature($"{header}.{payload}", secretKey);
            if (signature != expectedSignature) return null;

            // Giải mã payload
            string payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));
            var decodedPayload = JsonSerializer.Deserialize<JwtPayload>(payloadJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            // Kiểm tra hết hạn
            if (decodedPayload.Exp < DateTimeOffset.UtcNow.ToUnixTimeSeconds()) return null;

            return decodedPayload;
        }

        // Các hàm hỗ trợ mã hóa Base64Url và HMACSHA256
        private static string CreateSignature(string data, string secretKey)
        {
            var encoding = new UTF8Encoding();
            byte[] keyBytes = encoding.GetBytes(secretKey);
            byte[] dataBytes = encoding.GetBytes(data);

            using (var hmac = new HMACSHA256(keyBytes))
            {
                byte[] hash = hmac.ComputeHash(dataBytes);
                return Base64UrlEncode(hash);
            }
        }

        private static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Bỏ padding '='
            output = output.Replace('+', '-').Replace('/', '_');
            return output;
        }

        private static byte[] Base64UrlDecode(string input)
        {
            var output = input.Replace('-', '+').Replace('_', '/');
            switch (output.Length % 4) // Bù lại padding '='
            {
                case 2: output += "=="; break;
                case 3: output += "="; break;
            }
            return Convert.FromBase64String(output);
        }
    }
}