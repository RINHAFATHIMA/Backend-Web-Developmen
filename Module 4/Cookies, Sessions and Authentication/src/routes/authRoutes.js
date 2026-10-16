const express = require('express');
const bcrypt = require('bcryptjs');
const router = express.Router();

const userRepository = require('../db/userRepository');
const sessionStore = require('../session/sessionStore');
const requireSession = require('../middleware/requireSession');
const cookieOptions = require('../session/cookieOptions');

function authRequired(res) {
  return res.status(401).json({
    error: {
      code: 'AUTH_REQUIRED',
      message: 'Authentication required',
    },
  });
}

router.post('/login', async (req, res, next) => {
  try {
    const email =
      typeof req.body?.email === 'string'
        ? req.body.email.trim().toLowerCase()
        : '';

    const password =
      typeof req.body?.password === 'string' ? req.body.password : '';

    if (!email || !password) {
      return authRequired(res);
    }

    const user = await userRepository.findByEmail(email);

    const valid = user
      ? await bcrypt.compare(password, user.passwordHash)
      : false;

    if (!valid) {
      return authRequired(res);
    }

    const publicUser = await userRepository.findPublicById(user.id);
    if (!publicUser) {
      return authRequired(res);
    }

    const session = sessionStore.create(user.id);

    res.cookie('sid', session.id, {
      ...cookieOptions(),
      maxAge: Number(process.env.SESSION_TTL_MS || 3600000),
    });

    return res.status(200).json({ data: publicUser });
  } catch (error) {
    next(error);
  }
});

router.get('/me', requireSession, (req, res) => {
  return res.status(200).json({ data: req.user });
});

router.post('/logout', (req, res) => {
  const sid = req.signedCookies.sid;

  if (typeof sid === 'string') {
    sessionStore.destroy(sid);
  }

  res.clearCookie('sid', cookieOptions());
  return res.status(204).send();
});

module.exports = router;