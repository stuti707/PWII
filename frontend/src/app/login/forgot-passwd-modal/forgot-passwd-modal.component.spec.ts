import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ForgotPasswdModalComponent } from './forgot-passwd-modal.component';

describe('ForgotPasswdModalComponent', () => {
  let component: ForgotPasswdModalComponent;
  let fixture: ComponentFixture<ForgotPasswdModalComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ ForgotPasswdModalComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(ForgotPasswdModalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
