import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import {
  GenOTPDto,
  LoginDto,
  RegisterDto,
  VerifyOTPDto,
} from 'src/dto/auth.dto';
import { PrismaService } from 'src/prisma.service';
import * as bcrypt from 'bcryptjs';
import { generateSecretRandomBase32 } from 'src/lib/secret-base32';
import * as OTPAuth from 'otpauth';

@Injectable()
export class AuthService {
  constructor(private _prisma: PrismaService) {}

  /* Register new user */
  async register(registerDto: RegisterDto) {
    // Find if the user exist in my own database
    const existUser = await this._prisma.user.findUnique({
      where: {
        email: registerDto.email,
      },
    });

    // Error handling if the user exist
    if (existUser) {
      throw new HttpException('User exist', HttpStatus.CONFLICT);
    }

    // Hash password
    const hash = await bcrypt.hash(registerDto.password, 10);

    // Payload to be add in db
    const payload = {
      fullname: registerDto.fullname,
      email: registerDto.email,
      password: hash,
      otp_enabled: false,
    };

    //create the user
    await this._prisma.user.create({ data: payload });

    return { message: 'success' };
  }

  /* Login */
  async login(loginDto: LoginDto) {
    // Find if the user exist in my own database
    const existUser = await this._prisma.user.findUnique({
      where: {
        email: loginDto.email,
      },
    });

    // Error handling if the user exist
    if (!existUser) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    // Compare password is match or no
    const isMatch = await bcrypt.compare(loginDto.password, existUser.password);

    // Error handling if the password is invalid
    if (!isMatch) {
      throw new HttpException('Invalid password', HttpStatus.BAD_REQUEST);
    }

    // The return payload when i logged in
    const payload = {
      id: existUser.id,
      fullname: existUser.fullname,
      email: existUser.email,
      otp_enabled: existUser.otp_enabled,
      otp_validated: existUser.otp_validated,
    };

    return payload;
  }

  /* Generate one time password */
  async genOTP(genOTPDto: GenOTPDto) {
    // Find if the user exist in my own database
    const existUser = await this._prisma.user.findFirst({
      where: {
        id: genOTPDto.id,
      },
    });

    // Error handling if the user exist
    if (!existUser) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    // Generate the secret code
    const otp_secret = generateSecretRandomBase32();

    // 2 factor authentification
    let totp = new OTPAuth.TOTP({
      issuer: process.env.ISSUER_TOTP,
      label: process.env.LABEL_TOTP,
      algorithm: 'SHA1',
      digits: 6,
      period: 30, // Period to refresh code 30s for this
      secret: otp_secret, // or 'OTPAuth.Secret.fromBase32("NB2W45DFOIZA")'
    });

    // Generate uri for authentification
    const otp_authurl = totp.toString();

    // Insert data in the database using id user
    await this._prisma.user.update({
      where: { id: genOTPDto.id },
      data: {
        otp_secret,
        otp_authurl,
      },
    });

    return { otp_secret, otp_authurl };
  }

  /* Verify one time password */
  async verifyOTP(verifyOTPDto: VerifyOTPDto) {
    // Find if the user exist in my own database
    const existUser = await this._prisma.user.findFirst({
      where: {
        id: verifyOTPDto.id,
      },
    });

    // Error handling if the user exist
    if (!existUser) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    //verify existing code secret 2 factor authentification
    let totp = new OTPAuth.TOTP({
      issuer: process.env.ISSUER_TOTP,
      label: process.env.LABEL_TOTP,
      algorithm: 'SHA1',
      digits: 6,
      period: 30, // Period to refresh code 30s for this
      secret: existUser.otp_secret, // or 'OTPAuth.Secret.fromBase32("NB2W45DFOIZA")'
    });

    // Validate the token in db
    const delta = totp.validate({ token: verifyOTPDto.token });

    if (delta === null) {
      throw new HttpException('Invalid token', HttpStatus.BAD_REQUEST);
    }

    // Update the data of user
    const user = await this._prisma.user.update({
      where: {
        id: verifyOTPDto.id,
      },
      data: {
        otp_enabled: true,
      },
    });

    return {
      otp_enabled: user.otp_enabled,
    };
  }

  /* Verify One Time Password  */
  async validateOTP(validateOTPDto: VerifyOTPDto) {
    // Find if the user exist in my own database
    const existUser = await this._prisma.user.findFirst({
      where: {
        id: validateOTPDto.id,
      },
    });

    // Error handling if the user exist
    if (!existUser) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    //verify existing code secret 2 factor authentification
    let totp = new OTPAuth.TOTP({
      issuer: process.env.ISSUER_TOTP,
      label: process.env.LABEL_TOTP,
      algorithm: 'SHA1',
      digits: 6,
      period: 30, // Period to refresh code 30s for this
      secret: existUser.otp_secret, // or 'OTPAuth.Secret.fromBase32("NB2W45DFOIZA")'
    });

    // Validate the token in db
    const delta = totp.validate({ token: validateOTPDto.token });

    if (delta === null) {
      throw new HttpException('Invalid token', HttpStatus.BAD_REQUEST);
    }

    // Update the data of user
    const user = await this._prisma.user.update({
      where: {
        id: validateOTPDto.id,
      },
      data: {
        otp_validated: true,
      },
    });

    return {
      otp_validated: user.otp_validated,
    };
  }

  async disableOTP(disableOTPDto: GenOTPDto) {
    // Find if the user exist in my own database
    const existUser = await this._prisma.user.findFirst({
      where: {
        id: disableOTPDto.id,
      },
    });

    // Error handling if the user exist
    if (!existUser) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    // update user data
    const user = await this._prisma.user.update({
      where: {
        id: disableOTPDto.id,
      },
      data: {
        otp_enabled: false,
        otp_validated: false,
      },
    });

    return {
      otp_enabled: user.otp_enabled,
      otp_validated: user.otp_validated,
    };
  }

  /* Logout */
  async logout(body: GenOTPDto) {
    // Find if the user exist in my own database
    const existUser = await this._prisma.user.findFirst({
      where: {
        id: body.id,
      },
    });

    // Error handling if the user exist
    if (!existUser) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    // update user data
    const user = await this._prisma.user.update({
      where: {
        id: body.id,
      },
      data: {
        otp_validated: false,
      },
    });

    return {
      otp_validated: user.otp_validated,
    };
  }
}
