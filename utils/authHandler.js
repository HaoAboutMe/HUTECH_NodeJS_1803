let userController = require('../controllers/users')
let jwt = require('jsonwebtoken')
module.exports = {
    CheckLogin: async function (req, res, next) {
        try {
            let authHeader = req.headers.authorization;
            if (!authHeader) {
                res.status(401).send({
                    message: "Vui lòng cung cấp token (Authorization header)"
                })
                return;
            }

            // Hỗ trợ cả trường hợp có Bearer hoặc không có Bearer
            let token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;

            let result = jwt.verify(token, "secret")
            if (result.exp * 1000 < Date.now()) {
                res.status(401).send({
                    message: "Token đã hết hạn, vui lòng đăng nhập lại"
                })
                return;
            }
            let user = await userController.GetAnUserById(result.id);
            if (!user) {
                res.status(401).send({
                    message: "Người dùng không tồn tại hoặc đã bị xóa"
                })
                return;
            }
            req.user = user;
            next()
        } catch (error) {
            res.status(401).send({
                message: "Xác thực không thành công: " + error.message
            })
        }
    }
}