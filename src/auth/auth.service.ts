import { Injectable, Logger, OnModuleInit } from '@nestjs/common';

import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { RegisterUserDto } from './dto/register-user.dto';

import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('Auth Service');

  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB connected');
  }

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

  async registerUser(registerUserDto: RegisterUserDto) {
    /* const saltRounds = 10;
    const myPlaintextPassword = 's0//P4$$w0rD';

    const salt = bcrypt.genSaltSync(saltRounds);
    const hash = bcrypt.hashSync(myPlaintextPassword, salt);
    return hash; */
    const { email, name, password } = registerUserDto;

    try {
      const user = await this.user.findUnique({
        where: {
          email: email,
        },
      });

      if (user) {
        throw new RpcException({
          status: 400,
          message: 'User already exists',
        });
      }

      const newUser = await this.user.create({
        data: {
          email: email,
          password, //: bcrypt.hashSync(password, 10), // TODO: encriptar / hash
          name: name,
        },
      });

      const { password: __, ...rest } = newUser;

      return {
        user: rest,
        token: 'await this.signJWT(rest)',
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }
}
