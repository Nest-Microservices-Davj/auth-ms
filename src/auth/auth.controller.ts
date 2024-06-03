import { Controller, Logger, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { RegisterUserDto } from './dto/register-user.dto';
//import { LoginUserDto } from './dto';
import * as bcrypt from 'bcrypt';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  private readonly logger = new Logger('Auth Controller');

  @Post('login-test')
  async login() {
    console.log('Llega');
    const saltRounds = 10;
    const myPlaintextPassword = 's0//P4$$w0rD';
    try {
      const salt = bcrypt.genSaltSync(saltRounds);
      return salt;
    } catch (error) {
      console.log(error);
      throw new Error(error);
    }
  }

  @MessagePattern('auth.register.user')
  registerUser(@Payload() registerUserDto: RegisterUserDto) {
    return this.authService.registerUser(registerUserDto);
  }

  @MessagePattern('auth.login.user')
  loginUser() {
    return this.authService.login();
  }

  @MessagePattern('auth.verify.user')
  verifyToken() {
    this.logger.log('Verify user');
    return 'verify User';
  }
}
