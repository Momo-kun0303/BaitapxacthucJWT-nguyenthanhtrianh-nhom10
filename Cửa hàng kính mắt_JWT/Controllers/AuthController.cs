using Cửa_hàng_kính_mắt_JWT.Helpers; 
using Microsoft.AspNetCore.Mvc;

namespace Cửa_hàng_kính_mắt_JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;

        public AuthController(IConfiguration config)
        {
            _config = config;
        }

        public class LoginModel
        {
            public string Username { get; set; }
            public string Password { get; set; }
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginModel login)
        {
            string role = "";
            if (login.Username == "admin" && login.Password == "admin123") role = "Admin";
            else if (login.Username == "user" && login.Password == "user123") role = "User";

            if (string.IsNullOrEmpty(role))
                return Unauthorized(new { message = "Sai tài khoản hoặc mật khẩu!" });

            // Sử dụng hàm tự chế để tạo Token
            var secretKey = _config["Jwt:Key"];
            var jwtString = JwtHelper.GenerateToken(login.Username, role, secretKey);

            return Ok(new { token = jwtString, role = role });
        }

        // Test API: Chỉ Admin (Dùng CustomAuthorize thay cho [Authorize] mặc định)
        [CustomAuthorize(Roles = "Admin")]
        [HttpGet("admin-data")]
        public IActionResult GetAdminData()
        {
            return Ok(new { message = "Authorized: Chào mừng Admin. Bạn có quyền quản lý kho kính mắt." });
        }

        // Test API: Admin hoặc User đều được
        [CustomAuthorize(Roles = "Admin,User")]
        [HttpGet("user-data")]
        public IActionResult GetUserData()
        {
            // Cách lấy thông tin user đang gọi API từ JWT
            var currentUser = HttpContext.Items["User"] as JwtPayload;
            return Ok(new { message = $"Authorized: Xin chào {currentUser.Name}. Đây là giỏ hàng của bạn." });
        }
    }
}