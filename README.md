# 🛡️ ASP.NET Core 10 Advanced Security API with ML.NET Integration

A cutting-edge, production-ready authentication and authorization boilerplate built on **.NET 10**. 

This is not your average "login/register" tutorial project. It implements a robust, real-world security architecture that combines traditional defense mechanisms (JWT, 2FA, Active Session Management) with **Artificial Intelligence (ML.NET)** to dynamically evaluate user behavior, detect automated attacks, and calculate real-time risk scores.

## ✨ Key Features

- **🚀 .NET 10 Powered:** Built on the latest .NET SDK, utilizing modern C# features, minimal APIs structure, and optimal performance.
- **🧠 ML.NET Security Intelligence:**  
  - **Bot & Brute-Force Detection:** Utilizes `FastTree Binary Classification` to analyze request rates, failed attempts, and time-deltas to detect and block automated attacks dynamically.
  - **Anomaly Detection:** Employs `Randomized PCA` to flag suspicious login patterns based on IP changes, User-Agent anomalies, and temporal behaviors.
  - **Continuous Risk Scoring:** Uses `FastTree Regression` to calculate a user's real-time risk score (0-100) based on active sessions, revocation history, and failed access attempts.
- **🔐 Advanced Authentication Flow:**   
  - JWT Access Tokens with Automated Refresh Token Rotation.
  - Adaptive **Two-Factor Authentication (2FA)** triggered dynamically when the ML model detects an anomaly.
- **🛡️ Active Session Management:**   
  - Granular control to view, revoke, or permanently delete specific sessions.
  - "Revoke All Sessions" capability for compromised accounts.
- **🚦 Defensive Coding Patterns:** Integrated Rate Limiting (`StrictPolicy`), Password Hashing, Account Lockout policies, and robust Role/Permission-Based Access Control (RBAC).

## 🏗️ Architecture & AI Integration

The core of this API is the `AuthController`, which acts as the gatekeeper. Instead of relying purely on static rules, it consults three distinct Machine Learning services before issuing a token:

1. **`IBotDetectionService`:** Evaluates if the request velocity resembles a script.
2. **`IUserRiskScoringService`:** Determines the historical risk of the user account.
3. **`IAnomalyDetectionService`:** Checks if the current login context (IP, Time, Device) is unusual for the user.

If the AI flags a login as suspicious (but not overtly malicious), the system downgrades the authentication attempt and forces a temporary 2FA challenge via OTP.

## 🚀 Tech Stack

- **Framework:** .NET 10.0 (Web API)
- **AI / Machine Learning:** Microsoft.ML, Microsoft.Extensions.ML, Microsoft.ML.FastTree
- **Security:** JWT Bearer Authentication, Custom Password Hashing, RS256 Token Signing
- **Logging & Monitoring:** Serilog (Console & File Sinks)
- **Documentation:** OpenAPI (Swagger)

## 📁 Project Structure Highlights

- **`Controllers/AuthController.cs`**: The heart of the auth flow, orchestrating JWTs, ML predictions, and session management.
- **`Services/ML/`**:   
  - `AnomalyDetectionService.cs` (Randomized PCA)
  - `BotDetectionService.cs` (FastTree Classification)
  - `UserRiskScoringService.cs` (FastTree Regression)
- **`wwwroot/Jsons/`**: Lightweight JSON-based repository implementation for users, sessions, and tokens (perfect for boilerplate/testing).

## 🛠️ Getting Started

### Prerequisites

- [.NET 10.0 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) or later.
- Visual Studio 2026 / Rider / VS Code.

### Installation & Run

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/Mahdi-Yadi/WebApplicationJWT.git](https://github.com/Mahdi-Yadi/WebApplicationJWT.git)
   cd WebApplicationJWT
Restore Packages:

Bash
dotnet restore
ML Model Training:

Note: The ML models are configured to auto-train on the first run if the serialized .zip models are not found in the MLModels directory.

Run the API:

Bash
dotnet run
Explore the API:
Navigate to https://localhost:<port>/swagger to interact with the API endpoints.

🤝 Contributing
Contributions, issues, and feature requests are welcome! If you want to improve the ML training datasets or add new security features, feel free to open a Pull Request.

If you find this architectural approach helpful, please give it a ⭐️!

📜 License
This project is licensed under the MIT License - see the LICENSE file for details.
