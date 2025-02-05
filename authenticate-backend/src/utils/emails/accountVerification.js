export const verifyAccountEmail =(otp)=>{
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verify Your Account</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; text-align: center; padding: 50px; }
            .container { background: white; padding: 20px; border-radius: 10px; box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.2); width: 350px; margin: auto; }
            h2 { color: #333; }
            .otp-input { width: 100%; padding: 12px; margin: 10px 0; font-size: 18px; text-align: center; border: none; border-radius: 5px; box-shadow: 0px 3px 6px rgba(0, 0, 0, 0.2); }
            .submit-btn { background: #4CAF50; color: white; border: none; padding: 12px; width: 100%; font-size: 18px; border-radius: 5px; cursor: pointer; transition: 0.3s; }
            .submit-btn:hover { background: #45a049; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Verify Your Account</h2>
            <p>Use the OTP below to verify your account:</p>
            <input type="text" class="otp-input" value="${otp}" readonly>
            <p>Or enter this OTP manually: <strong>${otp}</strong></p>
        </div>
    </body>
    </html>`;
}
