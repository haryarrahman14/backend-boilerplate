import { Module } from '@nestjs/common';
import { StorageModule } from '../../platform/storage/storage.module.js';
import { AdminUsersController } from './admin-users.controller.js';
import { UsersController } from './users.controller.js';
import { UsersService } from './users.service.js';

@Module({
  imports: [StorageModule],
  controllers: [UsersController, AdminUsersController],
  providers: [UsersService],
})
export class UsersModule {}
