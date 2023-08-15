import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // To validate the input
  app.useGlobalPipes(new ValidationPipe());
  // To set the prefix of the path
  app.setGlobalPrefix('/api');
  // Enabling cors
  app.enableCors();
  // Port where the app run
  await app.listen(5000);
}
bootstrap();
