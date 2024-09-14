const express = require('express');
const router = express.Router();
const passport = require('passport');

const staffController = require('../controllers/staff_controller');

router.get('/sign-in', staffController.signIn);




// forgot password
router.get('/forgot-password', staffController.forgotPasswordGet);
router.post('/forgot-password', staffController.forgotPasswordPost);
router.get('/reset-password/:id/:token', staffController.resetPasswordGet);
router.post('/reset-password/:id/:token', staffController.resetPasswordPost);



router.post('/create-session', passport.authenticate(
    'local',
    { failureRedirect: '/admin/sign-in' },
), staffController.createSession);
router.get('/sign-out', staffController.destroySession);
module.exports = router;