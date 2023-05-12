import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthenticationService } from '../../../service/authentication.service';
//import { ResetPasswordModalService } from '../../../login/reset-passwd-modal/reset-passwd-modal.component';
import { ApiRequestService } from '../../../service/api-request.service';
import { ConstantsService } from '../../../service/constants.service';
import { OverlayLoader } from '../../shared/components/overlay-spinner/overlay-spinner.component';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { ResetPasswordModalService } from '../reset-passwd-modal/reset-passwd-modal.component';
import { UserService } from '../../../service/user.service';
import { ForgotPasswdModalService } from '../forgot-passwd-modal/forgot-passwd-modal.component';

@Component({
  selector: 'app-login-component',
  templateUrl: './login-component.html',
  styleUrls: ['./login-component.css']
})
export class LoginComponent implements OnInit {



  username = '';
  password = '';
  invalidLogin = false
  param = "";
  errMessage = "";
  destroy$: Subject<void> = new Subject<void>();

  constructor(private router: Router, private overlayloader: OverlayLoader,
    private loginservice: AuthenticationService,
    private resetModal: ResetPasswordModalService,
    private forgotModal: ForgotPasswdModalService,  
    private route: ActivatedRoute, private userService: UserService) { }

  ngOnInit() {
    this.route.params.pipe(takeUntil(this.destroy$)).subscribe(params => this.param = params['err']);
    if (this.param == "session expired") {
      this.errMessage = "Session has timed out, please login to continue";
      this.invalidLogin = true;
    }
  }

  ngOnDestory() {
    this.destroy$.next();
    this.destroy$.complete();
  }

  checkLogin() {

    if (this.username == "" || this.password == "") {
      this.invalidLogin = true;
      return;
    }

    let data = {};
    data['username'] = this.username;
    data['password'] = this.password;
    this.overlayloader.showOverlayLoader("Logging In");
    let result = this.loginservice.authenticate(this.username, this.password);
    result.then(data => {

      this.overlayloader.closeOverlayLoader();
      // this.userService.getUserPromise().then(obj =>{
      //   let res = this.userService.getAllowedPages()[0];
      //   this.router.navigate([res]);
      // });
      this.router.navigate(['/study']);

    }).catch(err => {
      console.log(err);
      if (err === 'Account Blocked') {
        this.invalidLogin = true;
        this.errMessage = "Account Blocked Contact Administrator";
      }
      else {
        this.invalidLogin = true;
        this.errMessage = err;
      }

      this.overlayloader.closeOverlayLoader();
    })
    // this.apiRequestService.post(ConstantsService.ENDPOINT_URL + 'login', data).subscribe(data => {

    //   sessionStorage.setItem("username", this.username);
    //   sessionStorage.setItem("userRole", JSON.stringify(data));
    //   this.invalidLogin = false;
    // }, err => {
    //   this.invalidLogin = true;
    //   console.log(err);
    // })

  }

  reset() {

    this.username = '';
    this.password = '';
  }

  resetPassword() {
    let dialog = this.resetModal.openModal("email");
  }


  forgotPassword() {

    let dialog = this.forgotModal.openModal("email");

  }

}
