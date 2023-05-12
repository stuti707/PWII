import { Component, OnInit, Inject, Injectable } from '@angular/core';
import { MatDialogRef, MAT_DIALOG_DATA, MatDialog } from '@angular/material/dialog';
import { ProgressSpinnerMode } from '@angular/material/progress-spinner';
import { ApiRequestService } from '../../../service/api-request.service';
import { ConstantsService } from '../../../service/constants.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-forgot-passwd-modal',
  templateUrl: './forgot-passwd-modal.component.html',
  styleUrls: ['./forgot-passwd-modal.component.css']
})

export class ForgotPasswdModalComponent implements OnInit {

  email_id;
  validEmail: boolean = false;
  resultText = "none";
  wait: boolean = false;
  result = ""
  showResult: boolean;
  showSpinner: boolean = false;
  otp: string = '';
  error: string = '';
  data1 = {};
  emailValidated: boolean = false;

  constructor(public dialogRef: MatDialogRef<ForgotPasswdModalComponent>, private router: Router,
    @Inject(MAT_DIALOG_DATA) public data: any, private apiRequestService: ApiRequestService) { }

  ngOnInit(): void {
  }


  validateEmail() {
    let regexp = new RegExp(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/);
    this.validEmail = regexp.test(this.email_id);
  }

  cancel() {
    this.dialogRef.close({ event: 'Cancel' });
  }

  resetPassword() {
    this.data1["email"] = this.email_id;
    this.data1["function_called"] = "Forgot Password"
    this.showSpinner = true;
    this.wait = true;
    this.showResult = false;

    this.apiRequestService.post(ConstantsService.ENDPOINT_URL + "forgot-passwd", this.data1).subscribe(data => {
      this.showSpinner = false;
      this.resultText = data;
      this.wait = false;
      this.result = "success";
      this.showResult = true;
      this.email_id = "";
      if (data == 'EMAIL SENT SUCCESSFULLY!') {
        this.emailValidated = true;
      }
    }, err => {
      this.resultText = err.error;
      this.showSpinner = false;
      this.wait = false;
      this.result = "FAIL";
      this.showResult = true;
    });
  }

  validateOtp() {
    this.showResult = false;
    this.data1["otp"] = this.otp;   
    this.apiRequestService.post(ConstantsService.ENDPOINT_URL + "otp-validation", this.data1).subscribe((data: any) => {
      this.result = "success";
      this.resultText = data;
      this.showResult = true;
      this.router.navigate(['/login/reset', data.username, data.token]);
    }, (err: any) => {
      this.resultText = err.error;
      this.result = "FAIL";
      this.showResult = true;
    });

  }
}

@Injectable(
  {
    providedIn: 'root'
  })
export class ForgotPasswdModalService {
  constructor(public dialog: MatDialog) {

  }

  openModal(type: string) {
    return this.dialog.open(ForgotPasswdModalComponent, {
      width: '40vw',
      height: '40vh',
      disableClose: true,
      data: { type: type }
    })
  }

}
