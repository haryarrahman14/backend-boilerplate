import { Module } from '@nestjs/common';
import { StorageModule } from '../../platform/storage/storage.module.js';
import { FilesController } from './files.controller.js';
import { FilesService } from './files.service.js';

@Module({
  imports: [StorageModule],
  controllers: [FilesController],
  providers: [FilesService],
})
export class FilesModule {}
