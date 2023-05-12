import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { LoginRoutingModule } from './login-routing.module';
import { LoginComponent } from './login-component/login-component';
import { DemoMaterialModule } from '../../demo-material-module';
import { ResetPasswordModalComponent, ResetPasswordModalService } from './reset-passwd-modal/reset-passwd-modal.component';
import { SharedModule } from '../shared/shared.module';
import { ResetPasswordComponent } from './reset-passwd/reset-passwd.component';
import { MatIconModule } from '@angular/material/icon';
import { FormsModule } from '@angular/forms';
import { ForgotPasswdModalComponent, ForgotPasswdModalService } from './forgot-passwd-modal/forgot-passwd-modal.component';


@NgModule({
  declarations: [LoginComponent, ResetPasswordModalComponent, ResetPasswordComponent, ForgotPasswdModalComponent],
  imports: [
    CommonModule,
    LoginRoutingModule,
    DemoMaterialModule,
    SharedModule,
    MatIconModule,
    FormsModule

  ],
  providers:[
    ResetPasswordModalService,
    ForgotPasswdModalService
  ]
})
export class LoginModule { }
