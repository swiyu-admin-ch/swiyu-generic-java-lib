package ch.admin.bj.swiyu.statuslist;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum TokenStatusListBit {
    VALID(0),
    REVOKED(1),
    SUSPENDED(2);

    private final int bitNumber;
}
