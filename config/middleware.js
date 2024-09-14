module.exports.setFlash = async function (req, res, next) {
    try {
        res.locals.flash = {
            'success': req.flash('success'),
            'error': req.flash('error')
        }
        next();
    }
    catch (error) {
        console.error('Error in setFlash middleware:', error);
        res.status(500).send('Internal Server Error');
    }
}
