package vti.dtn.admin_service.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
public class AccountDTO {
    private int id;
    private String username;
    private String firstName;
    private String lastName;
}
