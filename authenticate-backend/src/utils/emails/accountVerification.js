export const verifyAccountEmail = (otp) => {
    return `
      <!DOCTYPE html>
      <html>
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Verify Your Account</title>
          <style>
              body {
                  font-family: Arial, sans-serif;
                  background-color: #f2f2f2;
                  padding: 0;
                  margin: 0;
                  display: flex;
                  justify-content: center;
                  align-items: center;
                  height: 100vh;
              }
              .container {
                  background: linear-gradient(135deg, #ffcc00, #ff9966);
                  padding: 30px;
                  border-radius: 15px;
                  text-align: center;
                  box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
                  width: 420px;
                  display:flex;
                  justify-content:center;
                  align-item:center;
                  position: relative;
              }
              h2 {
                  color: #fff;
                  font-size: 24px;
                  margin-bottom: 20px;
                  font-weight: bold;
              }
              .otp-box {
                  background-color: #ffffff;
                  color: #333;
                  font-size: 32px;
                  padding: 20px;
                  border-radius: 10px;
                  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
                  font-weight: bold;
                  letter-spacing: 2px;
                  display: inline-block;
                  position: relative;
                  margin: 10px 0;
              }
              .otp-box::before {
                  content: "🎉";
                  font-size: 40px;
                  position: absolute;
                  top: -40px;
                  left: 50%;
                  transform: translateX(-50%);
              }
              .otp-box .otp-text {
                  display: inline-block;
                  font-size: 48px;
                  font-weight: 600;
                  letter-spacing: 5px;
              }
              .celebration {
                  font-size: 50px;
                  margin-top: 20px;
              }
  
              .link {
                  color: #ff6600;
                  font-weight: bold;
                  text-decoration: none;
                  font-size: 18px;
              }
              
              .link:hover {
                  text-decoration: underline;
              }
  
              /* Responsive styling */
              @media (max-width: 600px) {
                  .container {
                      width: 280px;
                      padding: 25px;
                  }
                  h2 {
                      font-size: 20px;
                  }
                  .otp-box {
                      font-size: 28px;
                      padding: 15px;
                  }
              }
          </style>
      </head>
      <body>
          <div class="container">
              <h2>🎉 Welcome to Our Service!</h2>
              <div class="otp-box">
                  <div class="otp-text">${otp}</div>
              </div>
              <div class="celebration">🎉🎈Let’s get started!</div>
              <p style="color: #fff; margin-top: 20px;">
                  Hi there, use the OTP above to verify your account and enjoy our service!
              </p>
              <p style="color: #fff;">
                  Didn’t get the OTP? <a href="#" class="link">Click here for a fresh one 🍽️</a>
              </p>
          </div>
      </body>
      </html>
    `;
  };
  