import { Component, OnInit, ViewChild } from '@angular/core';
import { ErrorStateMatcher } from '@angular/material/core';
import { MatTable } from '@angular/material/table';
import { UserEditModal } from './user-edit-modal/user-edit-modal.service';
import { ConstantsService } from '../../../../service/constants.service';
import { SnackbarService } from '../../../../service/snack-bar.service';
import { ApiRequestService } from '../../../../service/api-request.service';
import { OverlayLoader } from '../../../shared/components/overlay-spinner/overlay-spinner.component';
import { USERDTO } from '../../../../DTOs/UserDTO';
import { AbstractControl, FormControl, FormGroup, ValidationErrors, ValidatorFn, Validators } from '@angular/forms';
import { Roles } from '../../../../DTOs/Role';
import { Router } from '@angular/router'
import { Subject, Subscription } from 'rxjs';
import { takeUntil } from 'rxjs/operators';


const RolesData = [
    {
        viewValue: "Admin",
        value: "Admin"
    },
    {
        viewValue: "Designer",
        value: "Designer"
    },
    {
        viewValue: "Reviewer",
        value: "Reviewer"
    },
    {
        viewValue: "Global Librarian",
        value: "Global Librarian"
    },
    {
        viewValue: "Global Reviewer",
        value: "Global Reviewer"
    },

];


export class MyErrorStateMatcher implements ErrorStateMatcher {
    isErrorState(control: FormControl, form: import("@angular/forms").FormGroupDirective | import("@angular/forms").NgForm): boolean {
        throw new Error("Method not implemented.");
    }

}

@Component({
    selector: 'user-creation',
    templateUrl: './user-creation.component.html',
    styleUrls: ['./user-creation.component.css']
})
export class UserCreationComponent implements OnInit {

    @ViewChild(MatTable) table: MatTable<any>;
    userRole = RolesData
    userdata: USERDTO[];
    con_pass: string;
    pass_equal: boolean = false;
    userForm: FormGroup;
    user: USERDTO = new USERDTO();
    active: string;
    validEmail: boolean = false;
    passwordFormControl: FormControl;
    subs: Subscription[] = [];
    private destory$: Subject<void> = new Subject<void>();
    constructor(public userEditModal: UserEditModal, private snackbarService: SnackbarService,
        private overlayLoader: OverlayLoader, private apirequestService: ApiRequestService,
        private router: Router) {
        this.createUserForm();

    }

    ngOnInit() {
        //this.getUserList();

        this.getRoles();
        //this.passwordLen(this.userForm.get("password"));
        // this.passwordComplexity();

        this.userForm.get("confirm_password").valueChanges.pipe(takeUntil(this.destory$)).subscribe(data => {
            let pass = this.userForm.get("password").value;
            if (pass !== data) {
                this.userForm.get('confirm_password').setErrors({ password_doesnt_match: true });
            }
        });

        this.userForm.get('password').valueChanges.pipe(takeUntil(this.destory$)).subscribe(data =>{
            this.userForm.get('confirm_password').updateValueAndValidity();
        })
        // this.userForm.get("password").valueChanges.pipe(takeUntil(this.destory$)).subscribe(data=>{
        //     let pass = this.userForm.get("password").value;
        //     const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        //     const isValid = passwordRegex.test(pass);
        //     if(isValid !== true)
        //     {
        //         this.userForm.get('password').setErrors({password_not_complex:true});
        //     }
        // })
    }

    ngOnDestroy() {
        this.destory$.next();
        this.destory$.complete();
    }

    spaceValidator(control: AbstractControl) {

        if (control.value === "" || control.value?.toLowerCase().trim() !== '') {
            return null
        }
        return { valid_data: true };
    }



    // passwordValidator(control:AbstractControl){

    //     let pass = this.userForm.get('password').value
    //     if(control.value !== "" || control.value === pass) 
    //     {        return null 
    //     }
    //      return {password_doesnt_match:true};
    // }

    // passwordValidator(group:FormGroup){ 
    //     let pass = group.get('password').value;
    //     let confirmPass = group.get('confirm_Password').value
    //     return pass === confirmPass ? null : { password_doesnt_match: true }
    //   }

    // passwordComplexity(group:FormGroup){
    //     const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    //     const isValid = passwordRegex.test(group.get('password').value);
    //     return isValid ? null : { password_not_complex: true }
    // }

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
        if ( /[-+_!@#$%^&*,.?]/.test(control.value)) {
            return null
        }
        return { sp_character: true }
    }
    createUserForm() {
        this.userForm = new FormGroup({
            first_name: new FormControl("", [Validators.required, this.spaceValidator]),
            last_name: new FormControl("", [Validators.required, this.spaceValidator]),
            user_name: new FormControl("", [Validators.required, this.spaceValidator]),
            email_id: new FormControl("", [Validators.required, Validators.email, this.spaceValidator]),
            password: new FormControl("", [Validators.required,
            this.spaceValidator, this.passwordLen, this.passwordCapital, this.passwordLowerCase, this.validateDigit,this.validateSpCharacter]),
            confirm_password: new FormControl("", [Validators.required]),
            role: new FormControl("", [Validators.required]),
            activation_flag: new FormControl("", [Validators.required, this.spaceValidator]),
        })
    }

    createUser() {
        // if (!(this.con_pass == this.user.password)) {
        //     this.pass_equal = true;
        //     this.snackbarService.showSnackbar("Password does not match!", '', 2000);
        //     return;
        // }
        let user_value = this.userForm.value;
        delete user_value['confirm_password'];
        this.user = Object.assign(user_value);
        this.overlayLoader.showOverlayLoader("Creating User");
        this.apirequestService.post(ConstantsService.ENDPOINT_URL + "user", this.user).pipe(takeUntil(this.destory$)).subscribe(data => {

            this.overlayLoader.closeOverlayLoader();
            this.snackbarService.showSnackbar(data, "", 2000);
            this.user = new USERDTO();
            this.userForm.reset();
            this.moveBack()

        }, err => {

            if (err.error.includes("duplicate")) {
                let field = err.error.split("duplicate ")[1];
                if (field == 'email_id') {
                    this.userForm.get("email_id").setErrors({ "duplicate_email": true })
                }
                else if (field == 'user_name') {
                    this.userForm.get("user_name").setErrors({ "duplicate_user_name": true })
                }
            }
            this.user = new USERDTO();
            this.overlayLoader.closeOverlayLoader();
            this.snackbarService.showSnackbar("Error in User Creation", "", 2000);
        });


    }

    getRoles() {
        this.overlayLoader.showOverlayLoader("Fetching Roles");
        let sub = this.apirequestService.get(ConstantsService.ENDPOINT_URL + "get-roles").pipe(takeUntil(this.destory$)).subscribe(data => {
            this.userRole = data;
            this.overlayLoader.closeOverlayLoader();
        }, err => {
            this.overlayLoader.closeOverlayLoader();
            this.snackbarService.showSnackbar("ERROR In Fetching Roles!", '', 2000);
        });
        this.subs.push(sub);
    }


    // deleteUser(element) {
    //     this.overlayLoader.showOverlayLoader("Deleting User");

    //     let sub = this.apirequestService.put(ConstantsService.ENDPOINT_URL + "delete-user?userid=" + element._id.$oid, element._id.$oid).
    //         pipe(takeUntil(this.destory$)).subscribe(data => {

    //             this.overlayLoader.closeOverlayLoader();
    //             this.getUserList();
    //             this.snackbarService.showSnackbar(data, '', 2000);
    //         }, err => {
    //             this.overlayLoader.closeOverlayLoader();
    //             this.snackbarService.showSnackbar("User Deletion Failed!", '', 2000);
    //         });
    //     this.subs.push(sub);
    // }

    // getUserList() {
    //     this.overlayLoader.showOverlayLoader("Fetching Users");
    //     let sub = this.apirequestService.get(ConstantsService.ENDPOINT_URL + "user-list").pipe(takeUntil(this.destory$)).subscribe(data => {
    //         this.userdata = data;
    //         this.overlayLoader.closeOverlayLoader();
    //     }, err => {
    //         this.overlayLoader.closeOverlayLoader();
    //         this.snackbarService.showSnackbar("ERROR IN FETCHING USER LIST!", '', 2000);
    //     });
    //     this.subs.push(sub);

    // }

    // toggleUser(element) {
    //     this.overlayLoader.showOverlayLoader("Toggling User")
    //     let flag;
    //     if (element.activation_flag == "Active")
    //         flag = "InActive";
    //     else
    //         flag = "Active";


    //     let url = ConstantsService.ENDPOINT_URL + "set-user-status?userid=" + element._id.$oid + "&activation_flag=" + flag;
    //     let sub = this.apirequestService.put(url, element._id.$oid).pipe(takeUntil(this.destory$)).subscribe(data => {
    //         this.overlayLoader.closeOverlayLoader();
    //         this.getUserList();

    //     }, err => {
    //         this.snackbarService.showSnackbar("Error in setting status", '', 2000);
    //         this.overlayLoader.closeOverlayLoader();
    //     });
    //     this.subs.push(sub);
    // }


    resetUser() {
        this.user = new USERDTO();
        this.userForm.reset();
    }

    validateEmail() {
        let regexp = new RegExp(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/);
        this.validEmail = regexp.test(this.user.email_id);
    }

    matchPassword() {
        if (this.user.password != this.con_pass)
            this.snackbarService.showSnackbar("Password does not Match!", "", 1000);
        else
            this.snackbarService.showSnackbar("Password Matched!", "", 2000);
    }

    // editUser(element) {
    //     let dialogRef = this.userEditModal.openDialog(element);

    //     dialogRef.afterClosed().pipe(takeUntil(this.destory$)).subscribe(data => {
    //         if (data.event == "Update") {
    //             this.overlayLoader.showOverlayLoader("Updating User");
    //             let sub = this.apirequestService.put(ConstantsService.ENDPOINT_URL + "user", data.userdata).pipe(takeUntil(this.destory$)).subscribe(data1 => {
    //                 this.overlayLoader.closeOverlayLoader();
    //                 this.snackbarService.showSnackbar(data1, "", 2000);
    //                 this.getUserList();
    //             }, err => {
    //                 this.overlayLoader.closeOverlayLoader();
    //                 console.log(err);
    //                 this.snackbarService.showSnackbar("Update Failed", '', 2000);
    //             });
    //             this.subs.push(sub);
    //         }
    //         else {
    //             //this.overlayLoader.closeOverlayLoader();
    //         }
    //     }, err => {
    //         console.log(err);
    //         this.overlayLoader.closeOverlayLoader();
    //     })
    // }

    refreshTable() {
        this.table.renderRows();
    }

    moveBack() {
        this.router.navigate(['/user-mgnt-dashboard'])
    }
}