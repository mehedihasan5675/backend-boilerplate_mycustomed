import { NextFunction, Request, Response } from 'express'
import httpStatus from 'http-status'
import jwt, { JwtPayload } from 'jsonwebtoken'
import config from '../config'
import AppError from '../error/AppError'
import { TUserRole } from '../modules/user/user.interface'
import { User } from '../modules/user/user.model'
import catchAsync from '../utils/catchAsync'

const auth = (...requiredRoles: TUserRole[]) => {
  return catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers.authorization
    //if the token is sent from the client
    if (!token) {
      throw new AppError(httpStatus.UNAUTHORIZED, 'you are not authorized')
    }
    //check if the token is valid
    // invalid token
    const decoded = jwt.verify(
      token,
      config.jwt_access_secret as string,
    ) as JwtPayload
    //role checking
    const { role, userId, iat } = decoded

    //==
    //checking if the user is exist
    const user = await User.isUserExistsByCustomId(userId)
    if (!user) {
      throw new AppError(httpStatus.NOT_FOUND, 'This User is not found!')
    }
    //checking if the user is already deleted
    // const isDeleted = user?.isDeleted
    if (await User.isUserDeleted(userId)) {
      throw new AppError(httpStatus.NOT_FOUND, 'This User is already deleted! ')
    }
    //checking if the user is blocked
    // const isUserStatus = user?.status
    if ((await User.isUserStatus(userId)) === 'blocked') {
      throw new AppError(httpStatus.NOT_FOUND, 'This User is already blocked! ')
    }
    //==
    if (
      user.passwordChangeAt &&
      (await User.isJwtIssuedBeforePasswordChanged(
        user.passwordChangeAt,
        iat as number,
      ))
    ) {
      throw new AppError(httpStatus.NOT_FOUND, 'you are not Authorized! ')
    }
    if (requiredRoles && !requiredRoles.includes(role)) {
      throw new AppError(httpStatus.UNAUTHORIZED, 'you are not authorized')
    }

    // decoded undefined
    req.user = decoded as JwtPayload
    next()

    // jwt.verify(
    //   token,
    //   config.jwt_access_secret as string,
    //   function (err, decoded) {
    //     // err
    //     if (err) {
    //       throw new AppError(httpStatus.UNAUTHORIZED, 'you are not authorized')
    //     }

    //     //role checking
    //     const role = (decoded as JwtPayload)?.role
    //     if (requiredRoles && !requiredRoles.includes(role)) {
    //       throw new AppError(httpStatus.UNAUTHORIZED, 'you are not authorized')
    //     }

    //     // decoded undefined
    //     req.user = decoded as JwtPayload
    //     next()
    //   },
    // )
  })
}
export default auth
