import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { LoginDto, RegisterDto } from 'src/dto/auth.dto';
import { PrismaService } from 'src/prisma.service';
import * as bcrypt from 'bcryptjs';

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

  async genOTP() {
    return 'welcome to generate otp';
  }

  async verifyOTP() {
    return 'welcome to verify otp';
  }

  async validateOTP() {
    return 'welcome to validate otp';
  }

  async disableOTP() {
    return 'welcome to disable otp';
  }
}
