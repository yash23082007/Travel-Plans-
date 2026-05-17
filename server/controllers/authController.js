const User = require("../models/User");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");

// Register a new user
exports.register = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ msg: "Please provide all fields" });
    }

    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ msg: "User already exists" });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpire = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    // Create new user
    user = new User({
      name,
      email,
      password,
      isVerified: false,
      otp,
      otpExpire,
      otpResendAttempts: 0,
      otpLastResent: new Date(),
    });

    await user.save();

    // Send email with OTP code
    try {
      await sendEmail({
        email: user.email,
        subject: "Verify Your Email - PackGo",
        message: `Welcome to PackGo! Your 6-digit verification code is: ${otp}\n\nThis code will expire in 5 minutes.`,
      });
    } catch (emailErr) {
      console.error("Failed to send registration email:", emailErr);
    }

    // Dev mode log
    if (process.env.NODE_ENV === "development" || !process.env.SMTP_HOST) {
      console.log("\n=======================================================");
      console.log("🚀 DEV MODE: EMAIL VERIFICATION OTP GENERATED");
      console.log(`Email: ${user.email}`);
      console.log(`OTP Code: ${otp}`);
      console.log("=======================================================\n");
    }

    res.status(201).json({
      success: true,
      email: user.email,
      msg: "Account created! A 6-digit verification code has been sent to your email.",
    });
  } catch (err) {
    next(err);
  }
};

// Login user
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ msg: "Please provide email and password" });
    }

    // Check if user exists
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    // Prevent login if not verified
    if (!user.isVerified) {
      const now = Date.now();

      // Check if blocked (24-hour lockout)
      if (user.otpBlockedUntil && new Date(user.otpBlockedUntil).getTime() > now) {
        const timeLeft = new Date(user.otpBlockedUntil).getTime() - now;
        const hoursLeft = Math.ceil(timeLeft / (1000 * 60 * 60));
        return res.status(401).json({
          msg: `Please verify your email before logging in. You have reached the maximum number of resend attempts and are blocked from requesting new codes. Please try again in ${hoursLeft} hours.`,
          unverified: true,
          email: user.email,
          blocked: true,
          blockedUntil: user.otpBlockedUntil,
        });
      }

      // Generate a new OTP if current is missing or expired
      if (!user.otp || new Date(user.otpExpire).getTime() < now) {
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otp;
        user.otpExpire = new Date(now + 5 * 60 * 1000);
        user.otpLastResent = new Date();
        user.otpResendAttempts = 0;
        await user.save();

        try {
          await sendEmail({
            email: user.email,
            subject: "Verify Your Email - PackGo",
            message: `Your 6-digit verification code is: ${otp}\n\nThis code will expire in 5 minutes.`,
          });
        } catch (emailErr) {
          console.error("Failed to send verification email on login:", emailErr);
        }

        if (process.env.NODE_ENV === "development" || !process.env.SMTP_HOST) {
          console.log("\n=======================================================");
          console.log("🚀 DEV MODE: EMAIL VERIFICATION OTP GENERATED");
          console.log(`Email: ${user.email}`);
          console.log(`OTP Code: ${otp}`);
          console.log("=======================================================\n");
        }

        return res.status(401).json({
          msg: "Please verify your email before logging in. A new 6-digit code has been sent to your email.",
          unverified: true,
          email: user.email,
        });
      }

      // Current OTP is still valid, redirect user without sending a new email
      return res.status(401).json({
        msg: "Please verify your email before logging in. Use the verification code previously sent to your email.",
        unverified: true,
        email: user.email,
      });
    }

    // Create JWT token
    const payload = { user: { id: user.id } };
    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: "5d" },
      (err, token) => {
        if (err) throw err;
        res.json({
          token,
          user: { id: user.id, name: user.name, email: user.email },
        });
      },
    );
  } catch (err) {
    next(err);
  }
};

// Get user profile
exports.getProfile = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json(user);
  } catch (err) {
    next(err);
  }
};

// Update user profile
exports.updateProfile = async (req, res, next) => {
  try {
    const { name, email } = req.body;
    const updateFields = {};
    if (name) updateFields.name = name;
    if (email) updateFields.email = email;

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { $set: updateFields },
      { new: true },
    ).select("-password");

    res.json(user);
  } catch (err) {
    next(err);
  }
};

// Change password
exports.changePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(req.user.id);
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
      return res.status(400).json({ msg: "Current password is incorrect" });
    }

    user.password = newPassword;
    await user.save();

    res.json({ msg: "Password updated successfully" });
  } catch (err) {
    next(err);
  }
};

// Forgot Password
exports.forgotPassword = async (req, res, next) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      return res.status(404).json({ msg: "There is no user with that email" });
    }

    // Get reset token
    const resetToken = user.getResetPasswordToken();

    await user.save({ validateBeforeSave: false });

    // Create reset url
    // Assumes frontend is running on localhost:3000 during dev or the deployed URL
    const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";
    const resetUrl = `${frontendUrl}/reset-password/${resetToken}`;

    // Only print to console during local development for easy testing
    if (process.env.NODE_ENV === "development") {
      console.log("\n=======================================================");
      console.log("🚀 DEV MODE: PASSWORD RESET LINK GENERATED");
      console.log(resetUrl);
      console.log("=======================================================\n");
    }

    const message = `You are receiving this email because you (or someone else) has requested the reset of a password. Please make a PUT request to: \n\n ${resetUrl}`;

    try {
      // We still try to send the email, but if it takes too long, they already have the link above!
      await sendEmail({
        email: user.email,
        subject: "Password reset token",
        message,
      });

      res.status(200).json({ success: true, data: "Email sent successfully" });
    } catch (err) {
      console.error("Email sending failed:", err);

      // Reset the token fields since the email failed
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save({ validateBeforeSave: false });

      // Return a proper 500 error in production
      return res
        .status(500)
        .json({ msg: "Email could not be sent. Please try again later." });
    }
  } catch (err) {
    next(err);
  }
};

// Reset Password
exports.resetPassword = async (req, res, next) => {
  try {
    // Get hashed token
    const resetPasswordToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");

    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ msg: "Invalid token" });
    }

    // Set new password
    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();

    // Create JWT token and log user in automatically (optional)
    const payload = { user: { id: user.id } };
    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: "5d" },
      (err, token) => {
        if (err) throw err;
        res.json({
          msg: "Password reset successful",
          token,
          user: { id: user.id, name: user.name, email: user.email },
        });
      },
    );
  } catch (err) {
    next(err);
  }
};

// Verify OTP
exports.verifyOtp = async (req, res, next) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ msg: "Please provide email and verification code" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: "User does not exist" });
    }

    if (user.isVerified) {
      const payload = { user: { id: user.id } };
      return jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn: "5d" },
        (err, token) => {
          if (err) throw err;
          res.json({
            msg: "Email is already verified",
            token,
            user: { id: user.id, name: user.name, email: user.email },
          });
        }
      );
    }

    // Check if OTP matches
    if (user.otp !== otp) {
      return res.status(400).json({ msg: "Invalid verification code. Please check and try again." });
    }

    // Check if OTP is expired
    if (new Date(user.otpExpire).getTime() < Date.now()) {
      return res.status(400).json({ msg: "Verification code has expired. Please request a new one." });
    }

    // Successful verification
    user.isVerified = true;
    user.otp = null;
    user.otpExpire = null;
    user.otpResendAttempts = 0;
    user.otpLastResent = null;
    user.otpBlockedUntil = null;
    await user.save();

    // Create JWT token and log user in automatically
    const payload = { user: { id: user.id } };
    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: "5d" },
      (err, token) => {
        if (err) throw err;
        res.json({
          msg: "Email verified successfully! 🎉",
          token,
          user: { id: user.id, name: user.name, email: user.email },
        });
      }
    );
  } catch (err) {
    next(err);
  }
};

// Resend OTP
exports.resendOtp = async (req, res, next) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ msg: "Please provide email address" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: "User does not exist" });
    }

    if (user.isVerified) {
      return res.status(400).json({ msg: "This email is already verified" });
    }

    const now = Date.now();

    // Check if locked out (24-hour block)
    if (user.otpBlockedUntil && new Date(user.otpBlockedUntil).getTime() > now) {
      const timeLeft = new Date(user.otpBlockedUntil).getTime() - now;
      const hoursLeft = Math.ceil(timeLeft / (1000 * 60 * 60));
      return res.status(429).json({
        msg: `Too many resend attempts. You are blocked from requesting new codes. Please try again in ${hoursLeft} hours.`,
        blocked: true,
        blockedUntil: user.otpBlockedUntil
      });
    }

    // Enforce cooldown (60 seconds)
    if (user.otpLastResent && now - new Date(user.otpLastResent).getTime() < 60000) {
      const timeLeftSeconds = Math.ceil((60000 - (now - new Date(user.otpLastResent).getTime())) / 1000);
      return res.status(400).json({
        msg: `Please wait ${timeLeftSeconds} seconds before requesting another code.`
      });
    }

    // Check if they are about to exceed limits (limit is 5 attempts)
    if (user.otpResendAttempts >= 5) {
      const blockedTime = new Date(now + 24 * 60 * 60 * 1000);
      user.otpBlockedUntil = blockedTime;
      await user.save();

      return res.status(429).json({
        msg: "You have reached the maximum number of resend attempts (5). You are blocked from requesting new codes for 24 hours.",
        blocked: true,
        blockedUntil: blockedTime
      });
    }

    // Generate new OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Save to user
    user.otp = otp;
    user.otpExpire = new Date(now + 5 * 60 * 1000); // 5 minutes
    user.otpResendAttempts += 1;
    user.otpLastResent = new Date();
    await user.save();

    // Send Email
    try {
      await sendEmail({
        email: user.email,
        subject: "Verify Your Email - PackGo",
        message: `Your new 6-digit verification code is: ${otp}\n\nThis code will expire in 5 minutes.`,
      });
    } catch (emailErr) {
      console.error("Failed to send new verification email:", emailErr);
    }

    if (process.env.NODE_ENV === "development" || !process.env.SMTP_HOST) {
      console.log("\n=======================================================");
      console.log("🚀 DEV MODE: EMAIL VERIFICATION OTP GENERATED");
      console.log(`Email: ${user.email}`);
      console.log(`OTP Code: ${otp}`);
      console.log("=======================================================\n");
    }

    res.json({
      success: true,
      msg: "A new 6-digit verification code has been sent to your email.",
    });
  } catch (err) {
    next(err);
  }
};
