const Admin = require('../models/admin');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const env = require('../config/environment');
// Admin proflie page
module.exports.profile = async function (req, res) {
    try {
        const user = await Admin.findOne({ _id: req.user.id });

        if (!user) {
            return res.redirect('/');
        }

        // const data = await Inventory.find({});

        return res.render('admin_profile', {
            title: 'Admin Profile',
            // user: user,
            // data: data
        });
    } catch (error) {
        console.error('Error in profile:', error);
        return res.status(500).send('Internal Server Error');
    }
}
// Admin sign in page
module.exports.signIn = function (req, res) {
    try {
        if (req.isAuthenticated()) {
            return res.redirect('/admin/add-inventory');
        }

        return res.render('admin_sign_in', {
            title: 'Admin Sign In'
        });
    } catch (error) {
        console.error('Error in signIn:', error);
        return res.status(500).send('Internal Server Error');
    }
}


// Admin sign up page
module.exports.signUp = function (req, res) {
    try {
        if (req.isAuthenticated()) {
            return res.redirect('/admin/add-inventory');
        }

        return res.render('admin_sign_up', {
            title: 'Admin Sign Up'
        });
    } catch (error) {
        console.error('Error in signUp:', error);
        return res.status(500).send('Internal Server Error');
    }
}


// Admin forgot password
module.exports.forgotPasswordGet = function (req, res) {
    try {
        if (req.isAuthenticated()) {
            return res.redirect('/admin/add-inventory');
        }

        return res.render('admin_forgot_password', {
            title: 'Forgot Password'
        });
    } catch (error) {
        console.error('Error in forgotPasswordGet:', error);
        return res.status(500).send('Internal Server Error');
    }
}


// Admin forgot password 
module.exports.forgotPasswordPost = async function (req, res) {
    try {
        const email = req.body.email;
        const user = await Admin.findOne({ email: email });

        if (user) {
            const secret = env.JWT_SECRET + user.password;
            const payload = {
                email: user.email,
                id: user._id
            }
            const token = jwt.sign(payload, secret, { expiresIn: '15m' });
            const link = `http://localhost:8000/admin/reset-password/${user._id}/${token}`;
            const data = {
                name: user.name,
                email: user.email,
                link: link
            };
            mailer.sendForgotPassword(data);
            req.flash('success', 'Reset Password Email has been sent to you!');
            return res.redirect('back');
        } else {
            req.flash('error', 'No User found with this email ID');
            return res.redirect('/admin/sign-in');
        }
    } catch (err) {
        console.error('Error in forgotPasswordPost:', err);
        req.flash('error', 'Unable to reset password');
        return res.redirect('back');
    }
}


// Admin reset password Page
module.exports.resetPasswordGet = async function (req, res) {
    try {
        if (req.isAuthenticated()) {
            return res.redirect('/admin/add-inventory');
        }

        const { id, token } = req.params;
        const user = await Admin.findOne({ _id: id });

        if (user) {
            const secret = env.JWT_SECRET + user.password;

            try {
                const payload = jwt.verify(token, secret);
                return res.render('admin_reset_password', {
                    title: 'Reset Password',
                    email: user.email
                });
            } catch (err) {
                req.flash('error', 'Password Reset Link is no more active');
                return res.redirect('/admin/sign-in');
            }
        } else {
            req.flash('error', 'No User found with this ID');
            return res.redirect('/admin/sign-in');
        }
    } catch (err) {
        console.error('Error in resetPasswordGet:', err);
        return res.status(500).send('Internal Server Error');
    }
}

// Admin Reset Password Post
module.exports.resetPasswordPost = async function (req, res) {
    try {
        const { id, token } = req.params;
        const { password, confirm_password } = req.body;
        const user = await Admin.findOne({ _id: id });

        if (user) {
            const secret = env.JWT_SECRET + user.password;

            try {
                const payload = jwt.verify(token, secret);

                if (password === confirm_password) {
                    const hashedPassword = await bcrypt.hash(password, 10);
                    user.password = hashedPassword;
                    await user.save();
                    req.flash('success', 'Password Successfully Reset!');
                    return res.redirect('/admin/sign-in');
                } else {
                    req.flash('error', 'Password and Confirm Password do not match!');
                    return res.redirect('/admin/sign-in');
                }
            } catch (err) {
                req.flash('error', 'Unable to reset password');
                return res.redirect('/admin/sign-in');
            }
        } else {
            req.flash('error', 'No User found with this ID');
            return res.redirect('/admin/sign-in');
        }
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            req.flash('error', 'Password Reset Link has expired');
        } else if (error.name === 'JsonWebTokenError') {
            req.flash('error', 'Invalid Token');
        } else {
            req.flash('error', 'Unable to reset password');
        }
        console.error('Error in resetPasswordPost:', err);
        return res.redirect('/admin/sign-in');
    }
}


// Admin create account
module.exports.create = async function (req, res) {
    try {
        if (req.body.password !== req.body.confirm_password || req.body.key !== env.admin_key) {
            req.flash('error', 'Password or key does not match!!!');
            return res.redirect('back');
        }

        const user = await Admin.findOne({ email: req.body.email });

        if (!user) {
            const hashedPassword = await bcrypt.hash(req.body.password, 10);
            req.body.password = hashedPassword;
            await Admin.create(req.body);
            req.flash('success', 'Admin created successfully!!');
            return res.redirect('/admin/sign-in');
        } else {
            req.flash('error', 'This Admin already exists!!');
            throw new Error('This Admin already exists');
        }
    } catch (err) {
        console.error('Error in create:', err);
        req.flash('error', 'Unable to sign up');
        return res.redirect('back');
    }
}



// Admin create session
module.exports.createSession = async function (req, res) {
    try {
        req.flash('success', 'You have logged in successfully!!');
        return res.redirect('/admin/add-inventory');
    } catch (err) {
        console.error('Error in createSession:', err);
        return res.status(500).send('Internal Server Error');
    }
}


// admin logout

// Admin logout
module.exports.destroySession = async function (req, res) {
    try {
        req.logout(function (err) {
            if (err) {
                console.error('Error during logout:', err);
                return res.redirect('/'); // or handle the error in an appropriate way
            }

            req.flash('success', 'Logged out!!');
            return res.redirect('/');
        });
    } catch (err) {
        console.error('Error in destroySession:', err);
        return res.redirect('back');
    }
}