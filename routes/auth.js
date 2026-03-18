let express = require("express");
let router = express.Router();
let userController = require("../controllers/users");
let bcrypt = require("bcrypt");
const { CheckLogin } = require("../utils/authHandler");
let jwt = require("jsonwebtoken");
router.post("/register", async function (req, res, next) {
  try {
    let { username, password, email } = req.body;
    let newUser = await userController.CreateAnUser(
      username,
      password,
      email,
      "69ba44159c6c12540b929557",
    );
    res.send(newUser);
  } catch (error) {
    res.status(404).send({
      message: error.message,
    });
  }
});

router.post("/login", async function (req, res, next) {
  try {
    let { username, password } = req.body;
    let user = await userController.GetAnUserByUsername(username);
    if (!user) {
      res.status(404).send({
        message: "thong tin dang nhap khong dung",
      });
      return;
    }
    if (user.lockTime > Date.now()) {
      res.status(404).send({
        message: "ban dang bi ban",
      });
      return;
    }
    if (bcrypt.compareSync(password, user.password)) {
      user.loginCount = 0;
      await user.save();
      const fs = require("fs");
      let priK = fs.readFileSync("privateKey.pem");
      let token = jwt.sign(
        {
          id: user._id,
        },
        priK,
        {
          algorithm: "RS256",
          expiresIn: "1d",
        },
      );
      res.send(token);
    } else {
      user.loginCount++;
      if (user.loginCount == 3) {
        user.loginCount = 0;
        user.lockTime = Date.now() + 3600 * 1000;
      }
      await user.save();
      res.status(404).send({
        message: "thong tin dang nhap khong dung",
      });
    }
  } catch (error) {
    res.status(404).send({
      message: error.message,
    });
  }
});
router.get("/me", CheckLogin, function (req, res, next) {
  res.send(req.user);
});
router.post("/change-password", CheckLogin, async function (req, res, next) {
  try {
    let { oldPassword, newPassword } = req.body;
    // Validate newPassword
    if (
      !newPassword ||
      typeof newPassword !== "string" ||
      newPassword.length < 6
    ) {
      return res.status(400).send({
        message: "Mật khẩu mới phải có ít nhất 6 ký tự",
      });
    }
    if (oldPassword === newPassword) {
      return res.status(400).send({
        message: "Mật khẩu mới không được trùng với mật khẩu cũ",
      });
    }

    await userController.ChangePassword(req.user._id, oldPassword, newPassword);
    res.send({
      message: "Đổi mật khẩu thành công",
    });
  } catch (error) {
    res.status(400).send({
      message: error.message,
    });
  }
});
module.exports = router;
