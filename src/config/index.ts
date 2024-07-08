import dotenv from "dotenv";
dotenv.config();

// You can read the following blog to learn more about the code https://dev.to/md_enayeturrahman_2560e3/how-to-set-up-eslint-and-prettier-1nk6

export default {
  NODE_ENV: process.env.NODE_ENV,
  port: process.env.PORT,
  database_url: process.env.DATABASE_URL,
  bcrypt_salt_rounds: process.env.BCRYPT_SALT_ROUNDS,
  default_password: process.env.DEFAULT_PASS,
  jwt_access_secret: process.env.JWT_ACCESS_SECRET,
  jwt_refresh_secret: process.env.JWT_REFRESH_SECRET,
  jwt_access_expires_in: process.env.JWT_ACCESS_EXPIRES_IN,
  jwt_refresh_expires_in: process.env.JWT_REFRESH_EXPIRES_IN,
//   cloudinary_cloud_name:process.env.cloudinary_cloud_name,
//   cloudinary_api_key:process.env.cloudinary_api_key,
// cloudinary_api_secret:process.env.cloudinary_api_secret,

};
