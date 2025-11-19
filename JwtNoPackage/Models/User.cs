using System;
using System.Collections.Generic;

namespace JwtNoPackage.Models;

public partial class User
{
    public int Id { get; set; }

    public string Name { get; set; } = null!;

    public string Email { get; set; } = null!;

    public string Password { get; set; } = null!;

    public int RoleId { get; set; }

    public bool IsVerified { get; set; }

    public virtual Role? Role { get; set; } = null!;
}

public class LoginRequest
{
    public string Email { get; set; } = null!;

    public string Password { get; set; } = null!;
}
