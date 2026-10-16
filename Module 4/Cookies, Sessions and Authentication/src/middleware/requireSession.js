const sessionStore = require('../session/sessionStore');
const userRepository = require('../db/userRepository');

module.exports = async function requireSession(req, res, next) {
  try {
    const sid = req.signedCookies.sid;

    if (typeof sid !== 'string') {
      return res.status(401).json({
        error: {
          code: 'AUTH_REQUIRED',
          message: 'Authentication required',
        },
      });
    }

    const session = sessionStore.get(sid);

    if (!session) {
      return res.status(401).json({
        error: {
          code: 'AUTH_REQUIRED',
          message: 'Authentication required',
        },
      });
    }

    const user = await userRepository.findPublicById(session.userId);

    if (!user) {
      sessionStore.destroy(sid);

      return res.status(401).json({
        error: {
          code: 'AUTH_REQUIRED',
          message: 'Authentication required',
        },
      });
    }

    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
};