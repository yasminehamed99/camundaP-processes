package com.example.workflow.validation;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class ValidationResultsImpl implements ValidationResults {

    private final List<ValidationResult> infoMessages = new ArrayList<>();

    private final List<ValidationResult> warningMessages = new ArrayList<>();

    private final List<ValidationResult> errorMessages = new ArrayList<>();

    @Override
    public void addInfoMessage(String code, String category, String message) {
        ValidationResult validationMessage = new ValidationResultImpl(ValidationMessageType.INFO, code, category,
                message);

        infoMessages.add(validationMessage);
    }

    @Override
    public void addWarningMessage(String code, String category, String message) {
        ValidationResult validationMessage = new ValidationResultImpl(ValidationMessageType.WARNING, code, category,
                message);

        warningMessages.add(validationMessage);
    }

    @Override
    public void addErrorMessage(String code, String category, String message) {
        ValidationResult validationMessage = new ValidationResultImpl(ValidationMessageType.ERROR, code, category,
                message);

        errorMessages.add(validationMessage);
    }

    //TODO: validation all messages of type info
    @Override
    public void addInfoMessages(List<ValidationResult> infoMessages) {
        this.infoMessages.addAll(infoMessages);

    }

    //TODO: validation all messages of type warning
    @Override
    public void addWarningMessages(List<ValidationResult> warningMessages) {
        this.warningMessages.addAll(warningMessages);

    }

    //TODO: validation all messages of type error
    @Override
    public void addErrorMessages(List<ValidationResult> errorMessages) {
        this.errorMessages.addAll(errorMessages);
    }

    @Override
    public ValidationStatus getStatus() {

        if (!errorMessages.isEmpty()) {
            return ValidationStatus.ERROR;
        } else if (!warningMessages.isEmpty()) {
            return ValidationStatus.WARNING;
        } else {
            return ValidationStatus.PASS;
        }
    }

}
