import { IsNotEmpty, IsEmail } from 'class-validator';

/* Registeration DTO */
export class RegisterDto {
  @IsNotEmpty()
  fullname: string;

  @IsEmail()
  email: string;

  @IsNotEmpty()
  password: string;
}

/* Login DTO */
export class LoginDto {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  password: string;
}

/* GenOTP DTO */
export class GenOTPDto {
  @IsNotEmpty()
  id: string;
}

/* VerifyOTP DTO */
export class VerifyOTPDto {
  @IsNotEmpty()
  id: string;

  @IsNotEmpty()
  token: string;
}
