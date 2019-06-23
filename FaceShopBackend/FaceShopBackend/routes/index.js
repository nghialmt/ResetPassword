var API_KEY = 20101998

var express = require('express')
var router = express.Router()
var crypto = require('crypto')
var uuid = require('uuid')
var nodemailer = require('nodemailer')
var moment = require('moment')

//====================
//HASH AND SALT
//====================


var genRandomString = function (length) {
    return crypto.randomBytes(Math.ceil(length / 2))
        .toString('hex')
        .slice(0, length);
}

var sha512 = function (password, salt) {
    var hash = crypto.createHmac('sha512', salt);
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt: salt,
        passwordHash: value
    }
}

function saltHashPassword(userPassword) {
    var salt = genRandomString(16);
    var passwordData = sha512(userPassword, salt);
    return passwordData;

} 

//GET

//====================
//GENERATE PASSWORD
//====================
function generatePassword(passwordLength) {
    var numberChars = "0123456789";
    var upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    var lowerChars = "abcdefghijklmnopqrstuvwxyz";
    var allChars = numberChars + upperChars + lowerChars;
    var randPasswordArray = Array(passwordLength);
    randPasswordArray[0] = numberChars;
    randPasswordArray[1] = upperChars;
    randPasswordArray[2] = lowerChars;
    randPasswordArray = randPasswordArray.fill(allChars, 3);
    return shuffleArray(randPasswordArray.map(function (x) { return x[Math.floor(Math.random() * x.length)] })).join('');
}

function shuffleArray(array) {
    for (var i = array.length - 1; i > 0; i--) {
        var j = Math.floor(Math.random() * (i + 1));
        var temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
    return array;
}

//router.get('/', function (req, res, next) {
//    console.log(generatePassword(8));
//})


//====================
//RESET PASSWORD
//====================


router.get('/forgot', function (req, res, next) {
    if (req.query.key == API_KEY) {
        var email = req.query.email;

        if (email != null) {
            var initPassword = generatePassword(6);
            var encrypt = saltHashPassword(initPassword);
            var transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: 'francenghia@gmail.com',
                    pass: 'Nghia0942872954'
                }
            });

            var mailOptions = {
                from: 'francenghia@gmail.com',
                to: email,
                subject: 'RESET PASSWORD !',
                text: 'Bạn đang nhận được điều này bởi vì bạn (hoặc người khác) đã yêu cầu đặt lại mật khẩu cho tài khoản của bạn:\n'
                    + 'Mật khẩu của bạn là :' + initPassword + '\n'
                    + 'Vui lòng nhấp vào liên kết sau hoặc dán liên kết này vào trình duyệt của bạn để hoàn tất quy trình :'
                    + 'http://' + req.headers.host + '/reset-password?key=' + API_KEY + '&email=' + email + '&pass=' + encrypt.passwordHash + '&salt=' + encrypt.salt + '\n\n'
                    + 'Nếu bạn không yêu cầu chức năng này và mật khẩu bạn sẽ không bị thay đổi !'
            };

            transporter.sendMail(mailOptions, function (error, info) {
                if (error) {
                    res.send(JSON.stringify({ success: false, message: error.message }))
                } else {
                    res.send(JSON.stringify({ success: true, message: "Email sent :" + info.response }))
                }
            });
           // res.send(JSON.stringify({ success: true, message: email + "/" + initPassword }))
        } else {
            res.send(JSON.stringify({ success: false, message: "Missing email in query" }))
        }
    } else {
        res.send(JSON.stringify({ success: false , message:"Wrong API Key" }))
    }
})

router.get('/reset-password', function (req, res, next) {
    if (req.query.key == API_KEY) {
        var email = req.query.email;
        var pass = req.query.pass;
        var salt = req.query.salt;
        if (email != null && pass != null && salt!=null) {
            req.getConnection(function (error, conn) {
                conn.query(' UPDATE User SET password= ?,salt = ? WHERE email = ?', [pass, salt, email], function (err, rows, fields) {
                    if (err) {
                        res.status(500);
                        res.send(JSON.stringify({ success: false, message: err.message }))
                    } else {
                        res.send(JSON.stringify({ success: true, message: "Success" }))
                    }
                });
            })
        } else {
            res.send(JSON.stringify({ success: false, message: "Missing email or pass in query" }))
        }
    } else {
        res.send(JSON.stringify({ success: false, message: "Wrong API Key" }))
    }
})

module.exports = router