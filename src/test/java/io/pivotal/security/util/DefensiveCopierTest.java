package io.pivotal.security.util;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotSame;

@RunWith(JUnit4.class)
public class DefensiveCopierTest {
  final DefensiveCopier subject = new DefensiveCopier();

  @Test
  public void copyByteArray_DoesNotReturnReferenceToOriginalArray() throws Exception {
    byte[] originalArray = {  'a', 'b', 'c' };

    byte[] copiedArray = subject.copyByteArray(originalArray);

    assertNotSame(copiedArray, originalArray);
  }

  @Test
  public void copyByteArray_ReturnsArrayOfSameLength() throws Exception {
    byte[] originalArrayWith3Chars = {  '0', '1', '2' };

    byte[] copiedArray = subject.copyByteArray(originalArrayWith3Chars);

    assertThat(copiedArray.length, equalTo((originalArrayWith3Chars.length)));
  }
}