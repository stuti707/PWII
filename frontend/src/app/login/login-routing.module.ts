import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { LoginComponent } from './login-component/login-component';
import { ResetPasswordComponent } from './reset-passwd/reset-passwd.component';

const routes: Routes = [
  
{
  path:":err", component:LoginComponent
},
{
  path:'',
  component:LoginComponent
},
{
  path:"reset/:user_name/:token",
  component:ResetPasswordComponent
},
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class LoginRoutingModule { }
