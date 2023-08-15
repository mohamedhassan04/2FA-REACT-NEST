import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from 'src/dto/auth.dto';

@Controller('/')
export class AuthController {
  constructor(private readonly _authService: AuthService) {}

  //@Desc Register new user
  //@Methode POST
  //@Path api/register
  @Post('/register')
  register(@Body() registerDto: RegisterDto) {
    return this._authService.register(registerDto);
  }

  //@Desc login the user
  //@Methode POST
  //@Path api/login
  @Post('/login')
  login(@Body() loginDto: LoginDto) {
    return this._authService.login(loginDto);
  }

  //@Desc Generate OTP code
  //@Methode POST
  //@Path api/gen-otp
  @Post('/gen-otp')
  genOTP() {
    return this._authService.genOTP();
  }

  //@Desc Verify the OTP code
  //@Methode POST
  //@Path api/verify-otp
  @Post('/verify-otp')
  verifyOTP() {
    return this._authService.verifyOTP();
  }

  //@Desc Validate the OTP code generated
  //@Methode POST
  //@Path api/validate-otp
  @Post('/validate-otp')
  validateOTP() {
    return this._authService.validateOTP();
  }

  //@Desc Disabled the OTP code
  //@Methode POST
  //@Path api/disable-otp
  @Post('/disable-otp')
  disableOTP() {
    return this._authService.disableOTP();
  }
}
