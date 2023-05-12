import { Injectable, Component, Inject } from '@angular/core';
import { MatDialogRef, MAT_DIALOG_DATA, MatDialog } from '@angular/material/dialog';
import { ProgressSpinnerMode } from '@angular/material/progress-spinner';
import { ApiRequestService } from '../../../service/api-request.service';
import { ConstantsService } from '../../../service/constants.service';

@Component({
    selector: 'reset-passwd',
    templateUrl: './reset-passwd-modal.component.html',
    styleUrls: ['./reset-passwd-modal.component.css']
})
export class ResetPasswordModalComponent {

    email_id;
    validEmail: boolean = false;
    resultText = "none";
    wait: boolean = false;
    result = ""
    showResult: boolean;
    showSpinner: boolean = false;

    constructor(public dialogRef: MatDialogRef<ResetPasswordModalComponent>,
        @Inject(MAT_DIALOG_DATA) public data: any, private apiRequestService: ApiRequestService) {

    }

    validateEmail() {
        let regexp = new RegExp(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/);
        this.validEmail = regexp.test(this.email_id);
    }

    cancel() {
        this.dialogRef.close({ event: 'Cancel' });
    }

    resetPassword() {
        let data1 = {};
        data1["function_called"]="Reset Password"
        data1["email"] = this.email_id;
        this.showSpinner = true;
        this.wait = true;
        this.showResult = false;

        this.apiRequestService.post(ConstantsService.ENDPOINT_URL + "forgot-passwd", data1).subscribe(data => {
            this.showSpinner = false;
            this.resultText = data;
            this.wait = false;
            this.result = "success";
            this.showResult = true;
            this.email_id = "";
        }, err => {
            
            this.resultText = err.error;
            this.showSpinner = false;
            this.wait = false;
            this.result = "FAIL";
            this.showResult = true;
        });
    }
}

@Injectable(
    {
        providedIn: 'root'
    })
export class ResetPasswordModalService {
    constructor(public dialog: MatDialog) {

    }

    openModal(type) {
        return this.dialog.open(ResetPasswordModalComponent, {
            width: '40vw',
            height:'30vh',
            disableClose: true,
            data: { type: type }
        })
    }

}