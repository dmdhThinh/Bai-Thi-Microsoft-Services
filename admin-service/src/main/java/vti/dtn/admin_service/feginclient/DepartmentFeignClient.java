package vti.dtn.admin_service.feginclient;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import vti.dtn.admin_service.dto.DepartmentDTO;

import java.util.List;

@FeignClient(name = "department-service", path = "/api/v1/departments")
public interface DepartmentFeignClient {

    @GetMapping
    List<DepartmentDTO> getAllDepartments();

}
