import { Component, OnInit } from '@angular/core';
import { ApiRequestService } from '../../../service/api-request.service';
import { ConstantsService } from '../../../service/constants.service';
import { ActivatedRoute, Router } from '@angular/router';
import { AbstractControl, FormControl, FormGroup, Validators } from '@angular/forms';
import { OverlayLoader } from '../../shared/components/overlay-spinner/overlay-spinner.component';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

@Component({
    selector: 'reset',
    templateUrl: './reset-passwd.component.html',
    styleUrls: ['./reset-passwd.component.css']
})
export class ResetPasswordComponent implements OnInit {

    resultText;
    token;
    user_name = "";
    token_valid: boolean = false;
    isValidating: boolean = false;
    isUpdating: boolean = false;
    destroy$: Subject<boolean> = new Subject<boolean>();
    param = "";
    errMessage = "";
    password_form: FormGroup;
    result: boolean = false;
    passMatch: boolean = true;
    showform: boolean = false;
    constructor(private apiRequestService: ApiRequestService, private overlayLoader: OverlayLoader, private route: ActivatedRoute, public router: Router,) {
        this.createForm()
        this.route.params.subscribe(params => { this.token = params['token']; this.user_name = params['user_name'] });
        console.log(this.token)
        console.log(this.user_name);
        this.validateToken();

    }


    validateToken() {
        this.isValidating = true;
        this.isUpdating = false;
        this.overlayLoader.showOverlayLoader("Validating");
        let payload = {
            "reset_token": this.token,
            "user_name": this.user_name
        }
        this.apiRequestService.post(ConstantsService.ENDPOINT_URL + "validate-reset-password-token", payload).pipe(takeUntil(this.destroy$)).subscribe(data => {

            this.token_valid = true;
            this.showform = true;
            this.isValidating = false;
            this.overlayLoader.closeOverlayLoader();
        }, err => {
            this.isValidating = false;
            this.token_valid = false;
            setTimeout(() => {
                this.router.navigate(['./login'])
            }, 4000)

            this.overlayLoader.closeOverlayLoader();
        })
    }


    createForm() {
        this.password_form = new FormGroup({
            password: new FormControl("", [Validators.required,
            this.spaceValidator, this.passwordLen, this.passwordCapital, this.passwordLowerCase, this.validateDigit, this.validateSpCharacter]),
            confirm_password: new FormControl("", [Validators.required])
        }, )
    }


    passwordValidator(control: AbstractControl) {

        let confirmPass = control.get('confirm_password').value;
        let pass = control.get('password').value;
        return pass === confirmPass ? null : { password_doesnt_match: true }
    }

    spaceValidator(control: AbstractControl) {

        if (control.value === "" || control.value?.toLowerCase().trim() !== '') {
            return null
        }
        return { valid_data: true };
    }

    ngOnInit() {
        this.route.params.pipe(takeUntil(this.destroy$)).subscribe(params => this.param = params['err']);
        if (this.param == "session expired") {
            this.errMessage = "Session Expired!";
        }
        this.password_form.get("confirm_password").valueChanges.pipe(takeUntil(this.destroy$)).subscribe(data => {
            let pass = this.password_form.get("password").value;
            if (pass !== data) {
                this.password_form.get('confirm_password').setErrors({ password_doesnt_match: true });
            }
        })
    }
    ngOnDestory() {
        this.destroy$.next();
        this.destroy$.complete();
    }

    passwordLen(control: AbstractControl) {
        if (control.value.length >= 8) {
            return null
        }
        return { length: true }
    }
    passwordCapital(control: AbstractControl) {
        if (/[A-Z]+/.test(control.value)) {
            return null
        }
        return { capital: true }
    }
    passwordLowerCase(control: AbstractControl) {
        if (/[a-z]+/.test(control.value)) {
            return null
        }
        return { lowercase: true }
    }

    validateDigit(control: AbstractControl) {
        if (/[0-9]/.test(control.value)) {
            return null
        }
        return { digit: true }
    }
    validateSpCharacter(control: AbstractControl) {
        if (/[-+_!@#$%^&*,.?]/.test(control.value)) {
            return null
        }
        return { sp_character: true }
    }




    updatePassword() {
        let resetData = {};
        this.resultText = "Updating";
        this.isUpdating = true;
        resetData["password"] = this.password_form.get('password').value;
        resetData["token"] = this.token;
        resetData['user_name'] = this.user_name;

        this.apiRequestService.post(ConstantsService.ENDPOINT_URL + "reset", resetData).subscribe(data => {

            this.result = true;
            this.isUpdating = false;
            this.password_form.reset();
            this.resultText = "Password Updated! Redirecting You to Login Page...";
            setTimeout(() => {
                this.router.navigate(['login'])
            }, 3000);
        }, err => {
            console.log(err);
            this.isUpdating = false;
            this.result = false;

            if (err.error == "SAME_AS_OLD_PASSWORD")
                this.resultText = "Password should not be same as last 3 passwords."
            if (err.error == "URL Expired") {
                this.resultText = "Link Expired! Redirecting to Login Page..."
                setTimeout(() => {
                    this.router.navigate(['login'])
                }, 3000);
            }
            else
                this.resultText = "Error in password reset";

            setTimeout(() => {
                this.resultText = ""
            }, 1000)

        })

    }


}
