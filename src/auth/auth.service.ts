import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { SignupDto } from './dto/signup.dto';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) { }

  async signup(signupData: SignupDto) {
    const { email, password, name } = signupData;

    // Check if email is already in use
    const emailInUse = await this.prismaService.user.findUnique({
      where: {
        email: email,
      },
    });

    if (emailInUse) {
      throw new BadRequestException('Email is already in use');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user record in the database
    const newUser = await this.prismaService.user.create({
      data: {
        email: email,
        password: hashedPassword,
        name: name,
      },
      select: {
        email: true,
        name: true,
      },
    });

    // Return or handle the created user as needed
    return newUser;
  }




  async login(credentials: LoginDto) {

    // find if user exists by email 
    const { password, email } = credentials;
    // Check if email is already in use
    const user = await this.prismaService.user.findUnique({
      where: {
        email: email,
      },
    });

    if (!user) {
      // dont tell user that user with this email is not found, rather give more generic response. 
      throw new UnauthorizedException('Wrong Credentials');
    }
    // compare entered password with exitsitng password 
    const passwordMatch = await bcrypt.compare(password, user.password)
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong Credentials');
    }

    // generate jwt tokens and return them

    return this.generateuserTokens(user.id)
  }


  async generateuserTokens(userId) {

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync({ userId }, { // it uses the global secret for jwt form config folder and rt secret for refresh token
        expiresIn: '1h',
      }),
      this.jwtService.signAsync({ userId }, {
        secret: this.configService.get<string>('rt.secret'),
        expiresIn: '7d',
      }),
    ]);
    await this.storeRefreshToken(refreshToken, userId)
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }


  async storeRefreshToken(token: string, userId: string) {
    // Calculate the expiry date based on the '7d' duration
    const expiryDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days from now

    // Store the refresh token in the Prisma database
    await this.prismaService.refreshToken.create({
      data: {
        token,
        expiryDate,
        userId,
      },
    });
  }
}
