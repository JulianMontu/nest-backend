import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';

import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './entities/user.entity';
import * as bcryptjs from 'bcryptjs'
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto,LoginDto,UpdateAuthDto, CreateUserDto} from './dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService
  ){

  }
  
  async create(createUserDto: CreateUserDto): Promise<User> {
    try{
      const {password, ...userData} = createUserDto;

      const newUSer = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
        });
      
      //1- encriptar la contraseña

      //2- guardar el usuario
      //3- generar ej jwt
      await newUSer.save();
      const {password:_, ...user} = newUSer.toJSON();
      return user;
    }catch(error){
      if(error.code === 11000){
        throw new BadRequestException(`${createUserDto.email} already exists!`);
      }
      throw new InternalServerErrorException('Error');
    }
   
  }

  async register(registerUser:RegisterUserDto): Promise<LoginResponse>{
    const user = await this.create(registerUser);

    return {
      user: user,
      token: this.getJwtToken({id:user._id})
    }
  }

  async login(loginDto: LoginDto):Promise<LoginResponse>{
    /**
     * user {_id, name, email, roles}
     * Token -> asdas.asdasdas.asdad
     */

    const {email, password} = loginDto;

    const user = await this.userModel.findOne({email});

    if(!user){
      throw new UnauthorizedException('Not valid credentials - email');
    }

    if(!bcryptjs.compareSync(password, user.password)){
      throw new UnauthorizedException('Not valid credentials - password');
    }

    const {password:_, ...rest} = user.toJSON();

    return {
      user: rest,
      token: this.getJwtToken({id: user.id})
    }

  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

 async findUserById(userId: string){
    const user = await this.userModel.findById(userId);
    const {password, ...rest} = user.toJSON();
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload){
    const token = this.jwtService.sign(payload);
    return token;
  }
}
