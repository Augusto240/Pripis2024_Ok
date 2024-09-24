import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AnaliseComponent } from './analise.component';

describe('AnaliseComponent', () => {
  let component: AnaliseComponent;
  let fixture: ComponentFixture<AnaliseComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [AnaliseComponent]
    });
    fixture = TestBed.createComponent(AnaliseComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
