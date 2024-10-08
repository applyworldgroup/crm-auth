import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('signup')
  async signup(@Body() signupData: SignupDto) {
    return this.authService.signup(signupData)
  }
  @Post('login')
  async login(@Body() credentials: LoginDto) {
    return this.authService.login(credentials)
  }


}
