let userModel = require("../schemas/users");
let bcrypt = require("bcrypt");
module.exports = {
  CreateAnUser: async function (
    username,
    password,
    email,
    role,
    fullName,
    avatarUrl,
    status,
    loginCount,
  ) {
    let newItem = new userModel({
      username: username,
      password: password,
      email: email,
      fullName: fullName,
      avatarUrl: avatarUrl,
      status: status,
      role: role,
      loginCount: loginCount,
    });
    await newItem.save();
    return newItem;
  },
  GetAnUserByUsername: async function (username) {
    return await userModel.findOne({
      isDeleted: false,
      username: username,
    });
  },
  GetAnUserById: async function (id) {
    return await userModel.findOne({
      isDeleted: false,
      _id: id,
    });
  },
  ChangePassword: async function (userId, oldPassword, newPassword) {
    const user = await userModel.findById(userId);
    if (!user || user.isDeleted) {
      throw new Error("Người dùng không tồn tại");
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      throw new Error("Mật khẩu cũ không chính xác");
    }

    // Dùng findByIdAndUpdate với plain text để pre('findOneAndUpdate') hook
    // trong schema tự hash đúng 1 lần (tránh double-hash)
    await userModel.findByIdAndUpdate(userId, {
      password: newPassword,
    });
    return user;
  },
};
