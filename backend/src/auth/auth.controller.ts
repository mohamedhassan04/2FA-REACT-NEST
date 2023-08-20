import { Controller, Post, Body, HttpCode } from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  GenOTPDto,
  LoginDto,
  RegisterDto,
  VerifyOTPDto,
} from 'src/dto/auth.dto';

@Controller('/')
export class AuthController {
  constructor(private readonly _authService: AuthService) {}

  //@Desc Register new user
  //@Methode POST
  //@Path api/register
  @HttpCode(201)
  @Post('/register')
  register(@Body() registerDto: RegisterDto) {
    return this._authService.register(registerDto);
  }

  //@Desc login the user
  //@Methode POST
  //@Path api/login
  @HttpCode(200)
  @Post('/login')
  login(@Body() loginDto: LoginDto) {
    return this._authService.login(loginDto);
  }

  //@Desc Generate OTP code
  //@Methode POST
  //@Path api/gen-otp
  @HttpCode(200)
  @Post('/gen-otp')
  genOTP(@Body() genOTPDto: GenOTPDto) {
    return this._authService.genOTP(genOTPDto);
  }

  //@Desc Verify the OTP code
  //@Methode POST
  //@Path api/verify-otp
  @HttpCode(200)
  @Post('/verify-otp')
  verifyOTP(@Body() verifyOTPDto: VerifyOTPDto) {
    return this._authService.verifyOTP(verifyOTPDto);
  }

  //@Desc Validate the OTP code generated
  //@Methode POST
  //@Path api/validate-otp
  @HttpCode(200)
  @Post('/validate-otp')
  validateOTP(@Body() validateOTPDto: VerifyOTPDto) {
    return this._authService.validateOTP(validateOTPDto);
  }

  //@Desc Disabled the OTP code
  //@Methode POST
  //@Path api/disable-otp
  @HttpCode(200)
  @Post('/disable-otp')
  disableOTP(@Body() disableOTPDto: GenOTPDto) {
    return this._authService.disableOTP(disableOTPDto);
  }

  //@Desc Logout from user account
  //@Methode POST
  //@Path api/logout
  @HttpCode(200)
  @Post('/logout')
  logout(@Body() body: GenOTPDto) {
    return this._authService.logout(body);
  }
}
