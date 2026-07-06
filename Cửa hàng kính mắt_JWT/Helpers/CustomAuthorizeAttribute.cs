using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Cửa_hàng_kính_mắt_JWT.Helpers
{
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
    public class CustomAuthorizeAttribute : Attribute, IAuthorizationFilter
    {
        public string Roles { get; set; } // Nhận vai trò yêu cầu (vd: "Admin", "User")

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            // 1. Lấy secret key từ appsettings
            var config = context.HttpContext.RequestServices.GetService<IConfiguration>();
            var secretKey = config["Jwt:Key"];

            // 2. Lấy Token từ Header Authorization
            var authHeader = context.HttpContext.Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            {
                context.Result = new JsonResult(new { message = "Lỗi 401: Không tìm thấy Token" }) { StatusCode = 401 };
                return;
            }

            var token = authHeader.Substring("Bearer ".Length).Trim();

            // 3. Giải mã và kiểm tra hợp lệ
            var payload = JwtHelper.ValidateToken(token, secretKey);
            if (payload == null)
            {
                context.Result = new JsonResult(new { message = "Lỗi 401: Token không hợp lệ hoặc đã hết hạn" }) { StatusCode = 401 };
                return;
            }

            // 4. Kiểm tra phân quyền (Role)
            if (!string.IsNullOrEmpty(Roles))
            {
                var allowedRoles = Roles.Split(',').Select(r => r.Trim()).ToList();
                if (!allowedRoles.Contains(payload.Role))
                {
                    context.Result = new JsonResult(new { message = "Lỗi 403: Không có quyền truy cập chức năng này" }) { StatusCode = 403 };
                    return;
                }
            }

            // Lưu thông tin user vào HttpContext để dùng trong Controller nếu cần
            context.HttpContext.Items["User"] = payload;
        }
    }
}