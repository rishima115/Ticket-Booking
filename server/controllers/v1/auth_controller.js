
import User from '../../models/user.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// Register
export const register = async (req, res) => {
  try {
    const { email, password, name, mobileNum } = req.body || {};

    if (!email || !password || !name || !mobileNum) {
      return res.status(400).json({
        message: 'All fields are required'
      });
    }

    if (
      typeof email !== 'string' ||
      typeof password !== 'string' ||
      typeof name !== 'string' ||
      typeof mobileNum !== 'string'
    ) {
      return res.status(400).json({
        message: 'Invalid input format'
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const normalizedName = name.trim();
    const normalizedMobile = mobileNum.replace(/[\s()-]/g, '');

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const mobileRegex = /^\+?[1-9]\d{9,14}$/;

    if (!emailRegex.test(normalizedEmail)) {
      return res.status(400).json({
        message: 'Please enter a valid email address'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        message: 'Password must be at least 8 characters long'
      });
    }

    if (normalizedName.length < 2) {
      return res.status(400).json({
        message: 'Name must contain at least 2 characters'
      });
    }

    if (!mobileRegex.test(normalizedMobile)) {
      return res.status(400).json({
        message: 'Please enter a valid mobile number'
      });
    }

    const existingUser = await User.findOne({
      $or: [
        { email: normalizedEmail },
        { mobileNum: normalizedMobile }
      ]
    });

    if (existingUser) {
      return res.status(409).json({
        message: 'Email or mobile number is already registered'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      email: normalizedEmail,
      password: hashedPassword,
      name: normalizedName,
      mobileNum: normalizedMobile
    });

    return res.status(201).json({
      message: 'User registered successfully'
    });

  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        message: 'Email or mobile number is already registered'
      });
    }

    console.error('Registration error:', error);

    return res.status(500).json({
      message: 'Server error'
    });
  }
};

// Login
export const login = async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== 'string' ||
      typeof password !== 'string' ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: 'Email and password are required'
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.status(401).json({
        message: 'Invalid credentials'
      });
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      user.password
    );

    if (!isPasswordValid) {
      return res.status(401).json({
        message: 'Invalid credentials'
      });
    }

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '6h' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 6 * 60 * 60 * 1000
    });

    return res.status(200).json({
      message: 'Login successful',
      token
    });

  } catch (error) {
    console.error('Login error:', error);

    return res.status(500).json({
      message: 'Server error'
    });
  }
};
