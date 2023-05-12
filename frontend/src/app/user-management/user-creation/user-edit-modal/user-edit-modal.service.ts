import { Component, Injectable, Inject } from '@angular/core';
import { MatDialog, MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { USERDTO } from '../../../../../DTOs/UserDTO';

const Roles = [
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
        value: "Global Libararian"
    },
    {
        viewValue: "Global Reviewer",
        value: "Global Reviewer"
    },

];



@Component({

    selector: 'user-edit',
    templateUrl: './user-edit-modal.component.html',
    styleUrls: ['./user-edit-modal.component.css']

})
export class UserEditModalComponent {
    roles = Roles;
    userdata: USERDTO;
    constructor(public dialogRef: MatDialogRef<UserEditModalComponent>,
        @Inject(MAT_DIALOG_DATA) public data: any) {
        this.userdata = data.userdata;
        this.roles = data.userRole;
    }



    updateUser() {
        this.dialogRef.close({ event: "Update", userdata: this.userdata, status: "Rejected" });
    }

    cancel() {
        this.dialogRef.close({ event: "Cancel", status: "Rejected" });
    }
}


@Injectable({
    providedIn: 'root'
})
export class UserEditModal {
    constructor(public dialog: MatDialog) {

    }

    openDialog(userData, roles) {
        return this.dialog.open(UserEditModalComponent, {
            width: '1000px',
            data: { userdata: userData, userRole: roles }
        });
    }
}