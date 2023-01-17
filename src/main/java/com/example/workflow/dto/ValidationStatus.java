package com.example.workflow.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ValidationStatus {
    public String value;
    public String type;
}
