/*
   Copyright 2022 Evan Saulpaugh

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
package com.esaulpaugh.verification;

import com.esaulpaugh.headlong.util.FastHex;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ParserGenerator {

    private static final String FAILED_ARTIFACTS_3 =
            "    - aapt2-7.1.0-7984345-windows.jar (com.android.tools.build:aapt2:7.1.0-7984345) from repository Google\n" +
            "    - aapt2-7.1.0-7984345.pom (com.android.tools.build:aapt2:7.1.0-7984345) from repository Google";

    private static final String FAILED_ARTIFACTS_2 =
            "    - annotation-1.1.0.pom (androidx.annotation:annotation:1.1.0) from repository Google\n" +
            "    - collection-1.0.0.pom (androidx.collection:collection:1.0.0) from repository Google\n" +
            "    - core-1.3.2.aar (androidx.core:core:1.3.2) from repository Google\n" +
            "    - core-1.3.2.pom (androidx.core:core:1.3.2) from repository Google\n" +
            "    - core-common-2.0.0.pom (androidx.arch.core:core-common:2.0.0) from repository Google\n" +
            "    - customview-1.0.0.aar (androidx.customview:customview:1.0.0) from repository Google\n" +
            "    - customview-1.0.0.pom (androidx.customview:customview:1.0.0) from repository Google\n" +
            "    - gson-2.8.9.pom (com.google.code.gson:gson:2.8.9) from repository MavenRepo\n" +
            "    - gson-parent-2.8.9.pom (com.google.code.gson:gson-parent:2.8.9) from repository MavenRepo\n" +
            "    - headlong-5.6.1.module (com.esaulpaugh:headlong:5.6.1) from repository MavenRepo\n" +
            "    - lifecycle-common-2.0.0.pom (androidx.lifecycle:lifecycle-common:2.0.0) from repository Google\n" +
            "    - lifecycle-runtime-2.0.0.aar (androidx.lifecycle:lifecycle-runtime:2.0.0) from repository Google\n" +
            "    - lifecycle-runtime-2.0.0.pom (androidx.lifecycle:lifecycle-runtime:2.0.0) from repository Google\n" +
            "    - recyclerview-1.2.1.aar (androidx.recyclerview:recyclerview:1.2.1) from repository Google\n" +
            "    - recyclerview-1.2.1.module (androidx.recyclerview:recyclerview:1.2.1) from repository Google\n" +
            "    - versionedparcelable-1.1.0.aar (androidx.versionedparcelable:versionedparcelable:1.1.0) from repository Google\n" +
            "    - versionedparcelable-1.1.0.pom (androidx.versionedparcelable:versionedparcelable:1.1.0) from repository Google\n" +
            "    - annotation-1.1.0.jar (androidx.annotation:annotation:1.1.0) from repository Google\n" +
            "    - collection-1.0.0.jar (androidx.collection:collection:1.0.0) from repository Google\n" +
            "    - core-common-2.0.0.jar (androidx.arch.core:core-common:2.0.0) from repository Google\n" +
            "    - gson-2.8.9.jar (com.google.code.gson:gson:2.8.9) from repository MavenRepo\n" +
            "    - headlong-5.6.1.jar (com.esaulpaugh:headlong:5.6.1) from repository MavenRepo\n" +
            "    - lifecycle-common-2.0.0.jar (androidx.lifecycle:lifecycle-common:2.0.0) from repository Google";

    private static final String FAILED_ARTIFACTS =
            "    - FastInfoset-1.2.16.jar (com.sun.xml.fastinfoset:FastInfoset:1.2.16) from repository MavenRepo\n" +
            "    - FastInfoset-1.2.16.pom (com.sun.xml.fastinfoset:FastInfoset:1.2.16) from repository MavenRepo\n" +
            "    - aapt2-proto-7.1.0-7984345.jar (com.android.tools.build:aapt2-proto:7.1.0-7984345) from repository Google\n" +
            "    - aapt2-proto-7.1.0-7984345.module (com.android.tools.build:aapt2-proto:7.1.0-7984345) from repository Google\n" +
            "    - aaptcompiler-7.1.0.jar (com.android.tools.build:aaptcompiler:7.1.0) from repository Google\n" +
            "    - aaptcompiler-7.1.0.module (com.android.tools.build:aaptcompiler:7.1.0) from repository Google\n" +
            "    - all-1.2.0.pom (com.sun.activation:all:1.2.0) from repository MavenRepo\n" +
            "    - all-1.2.1.pom (com.sun.activation:all:1.2.1) from repository MavenRepo\n" +
            "    - android-device-provider-ddmlib-proto-30.1.0.jar (com.android.tools.utp:android-device-provider-ddmlib-proto:30.1.0) from repository Google\n" +
            "    - android-device-provider-ddmlib-proto-30.1.0.module (com.android.tools.utp:android-device-provider-ddmlib-proto:30.1.0) from repository Google\n" +
            "    - android-device-provider-gradle-proto-30.1.0.jar (com.android.tools.utp:android-device-provider-gradle-proto:30.1.0) from repository Google\n" +
            "    - android-device-provider-gradle-proto-30.1.0.module (com.android.tools.utp:android-device-provider-gradle-proto:30.1.0) from repository Google\n" +
            "    - android-test-plugin-host-additional-test-output-proto-30.1.0.jar (com.android.tools.utp:android-test-plugin-host-additional-test-output-proto:30.1.0) from repository Google\n" +
            "    - android-test-plugin-host-additional-test-output-proto-30.1.0.module (com.android.tools.utp:android-test-plugin-host-additional-test-output-proto:30.1.0) from repository Google\n" +
            "    - android-test-plugin-host-coverage-proto-30.1.0.jar (com.android.tools.utp:android-test-plugin-host-coverage-proto:30.1.0) from repository Google\n" +
            "    - android-test-plugin-host-coverage-proto-30.1.0.module (com.android.tools.utp:android-test-plugin-host-coverage-proto:30.1.0) from repository Google\n" +
            "    - android-test-plugin-host-retention-proto-30.1.0.jar (com.android.tools.utp:android-test-plugin-host-retention-proto:30.1.0) from repository Google\n" +
            "    - android-test-plugin-host-retention-proto-30.1.0.module (com.android.tools.utp:android-test-plugin-host-retention-proto:30.1.0) from repository Google\n" +
            "    - android-test-plugin-result-listener-gradle-proto-30.1.0.jar (com.android.tools.utp:android-test-plugin-result-listener-gradle-proto:30.1.0) from repository Google\n" +
            "    - android-test-plugin-result-listener-gradle-proto-30.1.0.module (com.android.tools.utp:android-test-plugin-result-listener-gradle-proto:30.1.0) from repository Google\n" +
            "    - animal-sniffer-annotations-1.17.jar (org.codehaus.mojo:animal-sniffer-annotations:1.17) from repository MavenRepo\n" +
            "    - animal-sniffer-annotations-1.17.pom (org.codehaus.mojo:animal-sniffer-annotations:1.17) from repository MavenRepo\n" +
            "    - animal-sniffer-parent-1.17.pom (org.codehaus.mojo:animal-sniffer-parent:1.17) from repository MavenRepo\n" +
            "    - annotations-13.0.jar (org.jetbrains:annotations:13.0) from repository MavenRepo\n" +
            "    - annotations-13.0.pom (org.jetbrains:annotations:13.0) from repository MavenRepo\n" +
            "    - annotations-30.1.0.jar (com.android.tools:annotations:30.1.0) from repository Google\n" +
            "    - annotations-30.1.0.module (com.android.tools:annotations:30.1.0) from repository Google\n" +
            "    - annotations-4.1.1.4.jar (com.google.android:annotations:4.1.1.4) from repository MavenRepo\n" +
            "    - annotations-4.1.1.4.pom (com.google.android:annotations:4.1.1.4) from repository MavenRepo\n" +
            "    - antlr4-4.5.3.jar (org.antlr:antlr4:4.5.3) from repository MavenRepo\n" +
            "    - antlr4-4.5.3.pom (org.antlr:antlr4:4.5.3) from repository MavenRepo\n" +
            "    - antlr4-master-4.5.3.pom (org.antlr:antlr4-master:4.5.3) from repository MavenRepo\n" +
            "    - apache-13.pom (org.apache:apache:13) from repository MavenRepo\n" +
            "    - apache-15.pom (org.apache:apache:15) from repository MavenRepo\n" +
            "    - apache-18.pom (org.apache:apache:18) from repository MavenRepo\n" +
            "    - apache-21.pom (org.apache:apache:21) from repository MavenRepo\n" +
            "    - apache-9.pom (org.apache:apache:9) from repository MavenRepo\n" +
            "    - apksig-7.1.0.jar (com.android.tools.build:apksig:7.1.0) from repository Google\n" +
            "    - apksig-7.1.0.module (com.android.tools.build:apksig:7.1.0) from repository Google\n" +
            "    - apkzlib-7.1.0.jar (com.android.tools.build:apkzlib:7.1.0) from repository Google\n" +
            "    - apkzlib-7.1.0.module (com.android.tools.build:apkzlib:7.1.0) from repository Google\n" +
            "    - asm-9.1.jar (org.ow2.asm:asm:9.1) from repository MavenRepo\n" +
            "    - asm-9.1.pom (org.ow2.asm:asm:9.1) from repository MavenRepo\n" +
            "    - asm-analysis-9.1.jar (org.ow2.asm:asm-analysis:9.1) from repository MavenRepo\n" +
            "    - asm-analysis-9.1.pom (org.ow2.asm:asm-analysis:9.1) from repository MavenRepo\n" +
            "    - asm-commons-9.1.jar (org.ow2.asm:asm-commons:9.1) from repository MavenRepo\n" +
            "    - asm-commons-9.1.pom (org.ow2.asm:asm-commons:9.1) from repository MavenRepo\n" +
            "    - asm-tree-9.1.jar (org.ow2.asm:asm-tree:9.1) from repository MavenRepo\n" +
            "    - asm-tree-9.1.pom (org.ow2.asm:asm-tree:9.1) from repository MavenRepo\n" +
            "    - asm-util-9.1.jar (org.ow2.asm:asm-util:9.1) from repository MavenRepo\n" +
            "    - asm-util-9.1.pom (org.ow2.asm:asm-util:9.1) from repository MavenRepo\n" +
            "    - auto-parent-6.pom (com.google.auto:auto-parent:6) from repository MavenRepo\n" +
            "    - auto-value-annotations-1.6.2.jar (com.google.auto.value:auto-value-annotations:1.6.2) from repository MavenRepo\n" +
            "    - auto-value-annotations-1.6.2.pom (com.google.auto.value:auto-value-annotations:1.6.2) from repository MavenRepo\n" +
            "    - auto-value-parent-1.6.2.pom (com.google.auto.value:auto-value-parent:1.6.2) from repository MavenRepo\n" +
            "    - baseLibrary-7.1.0.jar (com.android.databinding:baseLibrary:7.1.0) from repository Google\n" +
            "    - baseLibrary-7.1.0.module (com.android.databinding:baseLibrary:7.1.0) from repository Google\n" +
            "    - bcpkix-jdk15on-1.56.jar (org.bouncycastle:bcpkix-jdk15on:1.56) from repository MavenRepo\n" +
            "    - bcpkix-jdk15on-1.56.pom (org.bouncycastle:bcpkix-jdk15on:1.56) from repository MavenRepo\n" +
            "    - bcprov-jdk15on-1.56.jar (org.bouncycastle:bcprov-jdk15on:1.56) from repository MavenRepo\n" +
            "    - bcprov-jdk15on-1.56.pom (org.bouncycastle:bcprov-jdk15on:1.56) from repository MavenRepo\n" +
            "    - builder-7.1.0.jar (com.android.tools.build:builder:7.1.0) from repository Google\n" +
            "    - builder-7.1.0.module (com.android.tools.build:builder:7.1.0) from repository Google\n" +
            "    - builder-model-7.1.0.jar (com.android.tools.build:builder-model:7.1.0) from repository Google\n" +
            "    - builder-model-7.1.0.module (com.android.tools.build:builder-model:7.1.0) from repository Google\n" +
            "    - builder-test-api-7.1.0.jar (com.android.tools.build:builder-test-api:7.1.0) from repository Google\n" +
            "    - builder-test-api-7.1.0.module (com.android.tools.build:builder-test-api:7.1.0) from repository Google\n" +
            "    - bundletool-1.8.0.jar (com.android.tools.build:bundletool:1.8.0) from repository Google\n" +
            "    - bundletool-1.8.0.pom (com.android.tools.build:bundletool:1.8.0) from repository Google\n" +
            "    - checker-qual-2.5.8.pom (org.checkerframework:checker-qual:2.5.8) from repository MavenRepo\n" +
            "    - checker-qual-3.5.0.jar (org.checkerframework:checker-qual:3.5.0) from repository MavenRepo\n" +
            "    - checker-qual-3.5.0.pom (org.checkerframework:checker-qual:3.5.0) from repository MavenRepo\n" +
            "    - common-30.1.0.jar (com.android.tools:common:30.1.0) from repository Google\n" +
            "    - common-30.1.0.module (com.android.tools:common:30.1.0) from repository Google\n" +
            "    - commons-codec-1.10.jar (commons-codec:commons-codec:1.10) from repository MavenRepo\n" +
            "    - commons-codec-1.10.pom (commons-codec:commons-codec:1.10) from repository MavenRepo\n" +
            "    - commons-compress-1.20.jar (org.apache.commons:commons-compress:1.20) from repository MavenRepo\n" +
            "    - commons-compress-1.20.pom (org.apache.commons:commons-compress:1.20) from repository MavenRepo\n" +
            "    - commons-io-2.4.jar (commons-io:commons-io:2.4) from repository MavenRepo\n" +
            "    - commons-io-2.4.pom (commons-io:commons-io:2.4) from repository MavenRepo\n" +
            "    - commons-logging-1.2.jar (commons-logging:commons-logging:1.2) from repository MavenRepo\n" +
            "    - commons-logging-1.2.pom (commons-logging:commons-logging:1.2) from repository MavenRepo\n" +
            "    - commons-parent-25.pom (org.apache.commons:commons-parent:25) from repository MavenRepo\n" +
            "    - commons-parent-34.pom (org.apache.commons:commons-parent:34) from repository MavenRepo\n" +
            "    - commons-parent-35.pom (org.apache.commons:commons-parent:35) from repository MavenRepo\n" +
            "    - commons-parent-48.pom (org.apache.commons:commons-parent:48) from repository MavenRepo\n" +
            "    - core-proto-0.0.8-alpha07.jar (com.google.testing.platform:core-proto:0.0.8-alpha07) from repository Google\n" +
            "    - core-proto-0.0.8-alpha07.pom (com.google.testing.platform:core-proto:0.0.8-alpha07) from repository Google\n" +
            "    - crash-30.1.0.jar (com.android.tools.analytics-library:crash:30.1.0) from repository Google\n" +
            "    - crash-30.1.0.module (com.android.tools.analytics-library:crash:30.1.0) from repository Google\n" +
            "    - dagger-2.28.3.jar (com.google.dagger:dagger:2.28.3) from repository MavenRepo\n" +
            "    - dagger-2.28.3.pom (com.google.dagger:dagger:2.28.3) from repository MavenRepo\n" +
            "    - databinding-common-7.1.0.jar (androidx.databinding:databinding-common:7.1.0) from repository Google\n" +
            "    - databinding-common-7.1.0.module (androidx.databinding:databinding-common:7.1.0) from repository Google\n" +
            "    - databinding-compiler-common-7.1.0.jar (androidx.databinding:databinding-compiler-common:7.1.0) from repository Google\n" +
            "    - databinding-compiler-common-7.1.0.module (androidx.databinding:databinding-compiler-common:7.1.0) from repository Google\n" +
            "    - ddmlib-30.1.0.jar (com.android.tools.ddms:ddmlib:30.1.0) from repository Google\n" +
            "    - ddmlib-30.1.0.module (com.android.tools.ddms:ddmlib:30.1.0) from repository Google\n" +
            "    - dokka-core-1.4.32.jar (org.jetbrains.dokka:dokka-core:1.4.32) from repository MavenRepo\n" +
            "    - dokka-core-1.4.32.module (org.jetbrains.dokka:dokka-core:1.4.32) from repository MavenRepo\n" +
            "    - dvlib-30.1.0.jar (com.android.tools:dvlib:30.1.0) from repository Google\n" +
            "    - dvlib-30.1.0.module (com.android.tools:dvlib:30.1.0) from repository Google\n" +
            "    - error_prone_annotations-2.3.1.pom (com.google.errorprone:error_prone_annotations:2.3.1) from repository MavenRepo\n" +
            "    - error_prone_annotations-2.3.2.pom (com.google.errorprone:error_prone_annotations:2.3.2) from repository MavenRepo\n" +
            "    - error_prone_annotations-2.3.4.jar (com.google.errorprone:error_prone_annotations:2.3.4) from repository MavenRepo\n" +
            "    - error_prone_annotations-2.3.4.pom (com.google.errorprone:error_prone_annotations:2.3.4) from repository MavenRepo\n" +
            "    - error_prone_parent-2.3.1.pom (com.google.errorprone:error_prone_parent:2.3.1) from repository MavenRepo\n" +
            "    - error_prone_parent-2.3.2.pom (com.google.errorprone:error_prone_parent:2.3.2) from repository MavenRepo\n" +
            "    - error_prone_parent-2.3.4.pom (com.google.errorprone:error_prone_parent:2.3.4) from repository MavenRepo\n" +
            "    - failureaccess-1.0.1.jar (com.google.guava:failureaccess:1.0.1) from repository MavenRepo\n" +
            "    - failureaccess-1.0.1.pom (com.google.guava:failureaccess:1.0.1) from repository MavenRepo\n" +
            "    - fastinfoset-project-1.2.16.pom (com.sun.xml.fastinfoset:fastinfoset-project:1.2.16) from repository MavenRepo\n" +
            "    - fastutil-8.4.0.jar (it.unimi.dsi:fastutil:8.4.0) from repository MavenRepo\n" +
            "    - fastutil-8.4.0.pom (it.unimi.dsi:fastutil:8.4.0) from repository MavenRepo\n" +
            "    - flatbuffers-java-1.12.0.jar (com.google.flatbuffers:flatbuffers-java:1.12.0) from repository MavenRepo\n" +
            "    - flatbuffers-java-1.12.0.pom (com.google.flatbuffers:flatbuffers-java:1.12.0) from repository MavenRepo\n" +
            "    - gradle-7.1.0.jar (com.android.tools.build:gradle:7.1.0) from repository Google\n" +
            "    - gradle-7.1.0.module (com.android.tools.build:gradle:7.1.0) from repository Google\n" +
            "    - gradle-api-7.1.0.jar (com.android.tools.build:gradle-api:7.1.0) from repository Google\n" +
            "    - gradle-api-7.1.0.module (com.android.tools.build:gradle-api:7.1.0) from repository Google\n" +
            "    - grpc-api-1.21.1.jar (io.grpc:grpc-api:1.21.1) from repository MavenRepo\n" +
            "    - grpc-api-1.21.1.pom (io.grpc:grpc-api:1.21.1) from repository MavenRepo\n" +
            "    - grpc-context-1.21.1.jar (io.grpc:grpc-context:1.21.1) from repository MavenRepo\n" +
            "    - grpc-context-1.21.1.pom (io.grpc:grpc-context:1.21.1) from repository MavenRepo\n" +
            "    - grpc-core-1.21.1.jar (io.grpc:grpc-core:1.21.1) from repository MavenRepo\n" +
            "    - grpc-core-1.21.1.pom (io.grpc:grpc-core:1.21.1) from repository MavenRepo\n" +
            "    - grpc-netty-1.21.1.jar (io.grpc:grpc-netty:1.21.1) from repository MavenRepo\n" +
            "    - grpc-netty-1.21.1.pom (io.grpc:grpc-netty:1.21.1) from repository MavenRepo\n" +
            "    - grpc-protobuf-1.21.1.jar (io.grpc:grpc-protobuf:1.21.1) from repository MavenRepo\n" +
            "    - grpc-protobuf-1.21.1.pom (io.grpc:grpc-protobuf:1.21.1) from repository MavenRepo\n" +
            "    - grpc-protobuf-lite-1.21.1.jar (io.grpc:grpc-protobuf-lite:1.21.1) from repository MavenRepo\n" +
            "    - grpc-protobuf-lite-1.21.1.pom (io.grpc:grpc-protobuf-lite:1.21.1) from repository MavenRepo\n" +
            "    - grpc-stub-1.21.1.jar (io.grpc:grpc-stub:1.21.1) from repository MavenRepo\n" +
            "    - grpc-stub-1.21.1.pom (io.grpc:grpc-stub:1.21.1) from repository MavenRepo\n" +
            "    - gson-2.8.6.jar (com.google.code.gson:gson:2.8.6) from repository MavenRepo\n" +
            "    - gson-2.8.6.pom (com.google.code.gson:gson:2.8.6) from repository MavenRepo\n" +
            "    - gson-parent-2.8.6.pom (com.google.code.gson:gson-parent:2.8.6) from repository MavenRepo\n" +
            "    - guava-30.1-jre.jar (com.google.guava:guava:30.1-jre) from repository MavenRepo\n" +
            "    - guava-30.1-jre.pom (com.google.guava:guava:30.1-jre) from repository MavenRepo\n" +
            "    - guava-parent-26.0-android.pom (com.google.guava:guava-parent:26.0-android) from repository MavenRepo\n" +
            "    - guava-parent-30.1-jre.pom (com.google.guava:guava-parent:30.1-jre) from repository MavenRepo\n" +
            "    - httpclient-4.5.6.jar (org.apache.httpcomponents:httpclient:4.5.6) from repository MavenRepo\n" +
            "    - httpclient-4.5.6.pom (org.apache.httpcomponents:httpclient:4.5.6) from repository MavenRepo\n" +
            "    - httpcomponents-client-4.5.6.pom (org.apache.httpcomponents:httpcomponents-client:4.5.6) from repository MavenRepo\n" +
            "    - httpcomponents-core-4.4.10.pom (org.apache.httpcomponents:httpcomponents-core:4.4.10) from repository MavenRepo\n" +
            "    - httpcomponents-parent-10.pom (org.apache.httpcomponents:httpcomponents-parent:10) from repository MavenRepo\n" +
            "    - httpcore-4.4.10.jar (org.apache.httpcomponents:httpcore:4.4.10) from repository MavenRepo\n" +
            "    - httpcore-4.4.10.pom (org.apache.httpcomponents:httpcore:4.4.10) from repository MavenRepo\n" +
            "    - httpmime-4.5.6.jar (org.apache.httpcomponents:httpmime:4.5.6) from repository MavenRepo\n" +
            "    - httpmime-4.5.6.pom (org.apache.httpcomponents:httpmime:4.5.6) from repository MavenRepo\n" +
            "    - istack-commons-3.0.8.pom (com.sun.istack:istack-commons:3.0.8) from repository MavenRepo\n" +
            "    - istack-commons-runtime-3.0.8.jar (com.sun.istack:istack-commons-runtime:3.0.8) from repository MavenRepo\n" +
            "    - istack-commons-runtime-3.0.8.pom (com.sun.istack:istack-commons-runtime:3.0.8) from repository MavenRepo\n" +
            "    - j2objc-annotations-1.3.jar (com.google.j2objc:j2objc-annotations:1.3) from repository MavenRepo\n" +
            "    - j2objc-annotations-1.3.pom (com.google.j2objc:j2objc-annotations:1.3) from repository MavenRepo\n" +
            "    - jackson-annotations-2.11.1.jar (com.fasterxml.jackson.core:jackson-annotations:2.11.1) from repository MavenRepo\n" +
            "    - jackson-annotations-2.11.1.pom (com.fasterxml.jackson.core:jackson-annotations:2.11.1) from repository MavenRepo\n" +
            "    - jackson-base-2.11.1.pom (com.fasterxml.jackson:jackson-base:2.11.1) from repository MavenRepo\n" +
            "    - jackson-bom-2.11.1.pom (com.fasterxml.jackson:jackson-bom:2.11.1) from repository MavenRepo\n" +
            "    - jackson-core-2.11.1.jar (com.fasterxml.jackson.core:jackson-core:2.11.1) from repository MavenRepo\n" +
            "    - jackson-core-2.11.1.pom (com.fasterxml.jackson.core:jackson-core:2.11.1) from repository MavenRepo\n" +
            "    - jackson-databind-2.11.1.jar (com.fasterxml.jackson.core:jackson-databind:2.11.1) from repository MavenRepo\n" +
            "    - jackson-databind-2.11.1.pom (com.fasterxml.jackson.core:jackson-databind:2.11.1) from repository MavenRepo\n" +
            "    - jackson-dataformat-xml-2.11.1.jar (com.fasterxml.jackson.dataformat:jackson-dataformat-xml:2.11.1) from repository MavenRepo\n" +
            "    - jackson-dataformat-xml-2.11.1.pom (com.fasterxml.jackson.dataformat:jackson-dataformat-xml:2.11.1) from repository MavenRepo\n" +
            "    - jackson-module-jaxb-annotations-2.11.1.jar (com.fasterxml.jackson.module:jackson-module-jaxb-annotations:2.11.1) from repository MavenRepo\n" +
            "    - jackson-module-jaxb-annotations-2.11.1.pom (com.fasterxml.jackson.module:jackson-module-jaxb-annotations:2.11.1) from repository MavenRepo\n" +
            "    - jackson-module-kotlin-2.11.1.jar (com.fasterxml.jackson.module:jackson-module-kotlin:2.11.1) from repository MavenRepo\n" +
            "    - jackson-module-kotlin-2.11.1.pom (com.fasterxml.jackson.module:jackson-module-kotlin:2.11.1) from repository MavenRepo\n" +
            "    - jackson-modules-base-2.11.1.pom (com.fasterxml.jackson.module:jackson-modules-base:2.11.1) from repository MavenRepo\n" +
            "    - jackson-parent-2.11.pom (com.fasterxml.jackson:jackson-parent:2.11) from repository MavenRepo\n" +
            "    - jakarta.activation-api-1.2.1.jar (jakarta.activation:jakarta.activation-api:1.2.1) from repository MavenRepo\n" +
            "    - jakarta.activation-api-1.2.1.pom (jakarta.activation:jakarta.activation-api:1.2.1) from repository MavenRepo\n" +
            "    - jakarta.xml.bind-api-2.3.2.jar (jakarta.xml.bind:jakarta.xml.bind-api:2.3.2) from repository MavenRepo\n" +
            "    - jakarta.xml.bind-api-2.3.2.pom (jakarta.xml.bind:jakarta.xml.bind-api:2.3.2) from repository MavenRepo\n" +
            "    - jakarta.xml.bind-api-parent-2.3.2.pom (jakarta.xml.bind:jakarta.xml.bind-api-parent:2.3.2) from repository MavenRepo\n" +
            "    - javapoet-1.10.0.jar (com.squareup:javapoet:1.10.0) from repository MavenRepo\n" +
            "    - javapoet-1.10.0.pom (com.squareup:javapoet:1.10.0) from repository MavenRepo\n" +
            "    - javawriter-2.5.0.jar (com.squareup:javawriter:2.5.0) from repository MavenRepo\n" +
            "    - javawriter-2.5.0.pom (com.squareup:javawriter:2.5.0) from repository MavenRepo\n" +
            "    - javax.activation-1.2.0.jar (com.sun.activation:javax.activation:1.2.0) from repository MavenRepo\n" +
            "    - javax.activation-1.2.0.pom (com.sun.activation:javax.activation:1.2.0) from repository MavenRepo\n" +
            "    - javax.inject-1.jar (javax.inject:javax.inject:1) from repository MavenRepo\n" +
            "    - javax.inject-1.pom (javax.inject:javax.inject:1) from repository MavenRepo\n" +
            "    - jaxb-bom-2.3.2.pom (org.glassfish.jaxb:jaxb-bom:2.3.2) from repository MavenRepo\n" +
            "    - jaxb-bom-ext-2.3.2.pom (com.sun.xml.bind:jaxb-bom-ext:2.3.2) from repository MavenRepo\n" +
            "    - jaxb-parent-2.3.2.pom (com.sun.xml.bind.mvn:jaxb-parent:2.3.2) from repository MavenRepo\n" +
            "    - jaxb-runtime-2.3.2.jar (org.glassfish.jaxb:jaxb-runtime:2.3.2) from repository MavenRepo\n" +
            "    - jaxb-runtime-2.3.2.pom (org.glassfish.jaxb:jaxb-runtime:2.3.2) from repository MavenRepo\n" +
            "    - jaxb-runtime-parent-2.3.2.pom (com.sun.xml.bind.mvn:jaxb-runtime-parent:2.3.2) from repository MavenRepo\n" +
            "    - jaxb-txw-parent-2.3.2.pom (com.sun.xml.bind.mvn:jaxb-txw-parent:2.3.2) from repository MavenRepo\n" +
            "    - jdom2-2.0.6.jar (org.jdom:jdom2:2.0.6) from repository MavenRepo\n" +
            "    - jdom2-2.0.6.pom (org.jdom:jdom2:2.0.6) from repository MavenRepo\n" +
            "    - jetifier-core-1.0.0-beta09.jar (com.android.tools.build.jetifier:jetifier-core:1.0.0-beta09) from repository Google\n" +
            "    - jetifier-core-1.0.0-beta09.pom (com.android.tools.build.jetifier:jetifier-core:1.0.0-beta09) from repository Google\n" +
            "    - jetifier-processor-1.0.0-beta09.jar (com.android.tools.build.jetifier:jetifier-processor:1.0.0-beta09) from repository Google\n" +
            "    - jetifier-processor-1.0.0-beta09.pom (com.android.tools.build.jetifier:jetifier-processor:1.0.0-beta09) from repository Google\n" +
            "    - jimfs-1.1.jar (com.google.jimfs:jimfs:1.1) from repository MavenRepo\n" +
            "    - jimfs-1.1.pom (com.google.jimfs:jimfs:1.1) from repository MavenRepo\n" +
            "    - jimfs-parent-1.1.pom (com.google.jimfs:jimfs-parent:1.1) from repository MavenRepo\n" +
            "    - jna-5.6.0.jar (net.java.dev.jna:jna:5.6.0) from repository MavenRepo\n" +
            "    - jna-5.6.0.pom (net.java.dev.jna:jna:5.6.0) from repository MavenRepo\n" +
            "    - jna-platform-5.6.0.jar (net.java.dev.jna:jna-platform:5.6.0) from repository MavenRepo\n" +
            "    - jna-platform-5.6.0.pom (net.java.dev.jna:jna-platform:5.6.0) from repository MavenRepo\n" +
            "    - jopt-simple-4.9.jar (net.sf.jopt-simple:jopt-simple:4.9) from repository MavenRepo\n" +
            "    - jopt-simple-4.9.pom (net.sf.jopt-simple:jopt-simple:4.9) from repository MavenRepo\n" +
            "    - jose4j-0.7.0.jar (org.bitbucket.b_c:jose4j:0.7.0) from repository MavenRepo\n" +
            "    - jose4j-0.7.0.pom (org.bitbucket.b_c:jose4j:0.7.0) from repository MavenRepo\n" +
            "    - json-20180813.jar (org.json:json:20180813) from repository MavenRepo\n" +
            "    - json-20180813.pom (org.json:json:20180813) from repository MavenRepo\n" +
            "    - json-simple-1.1.jar (com.googlecode.json-simple:json-simple:1.1) from repository MavenRepo\n" +
            "    - json-simple-1.1.pom (com.googlecode.json-simple:json-simple:1.1) from repository MavenRepo\n" +
            "    - jsoup-1.13.1.jar (org.jsoup:jsoup:1.13.1) from repository MavenRepo\n" +
            "    - jsoup-1.13.1.pom (org.jsoup:jsoup:1.13.1) from repository MavenRepo\n" +
            "    - jsr305-3.0.2.jar (com.google.code.findbugs:jsr305:3.0.2) from repository MavenRepo\n" +
            "    - jsr305-3.0.2.pom (com.google.code.findbugs:jsr305:3.0.2) from repository MavenRepo\n" +
            "    - juniversalchardet-1.0.3.jar (com.googlecode.juniversalchardet:juniversalchardet:1.0.3) from repository MavenRepo\n" +
            "    - juniversalchardet-1.0.3.pom (com.googlecode.juniversalchardet:juniversalchardet:1.0.3) from repository MavenRepo\n" +
            "    - jvnet-parent-1.pom (net.java:jvnet-parent:1) from repository MavenRepo\n" +
            "    - kotlin-reflect-1.4.32.jar (org.jetbrains.kotlin:kotlin-reflect:1.4.32) from repository MavenRepo\n" +
            "    - kotlin-reflect-1.4.32.pom (org.jetbrains.kotlin:kotlin-reflect:1.4.32) from repository MavenRepo\n" +
            "    - kotlin-stdlib-1.4.32.jar (org.jetbrains.kotlin:kotlin-stdlib:1.4.32) from repository MavenRepo\n" +
            "    - kotlin-stdlib-1.4.32.pom (org.jetbrains.kotlin:kotlin-stdlib:1.4.32) from repository MavenRepo\n" +
            "    - kotlin-stdlib-common-1.4.32.jar (org.jetbrains.kotlin:kotlin-stdlib-common:1.4.32) from repository MavenRepo\n" +
            "    - kotlin-stdlib-common-1.4.32.pom (org.jetbrains.kotlin:kotlin-stdlib-common:1.4.32) from repository MavenRepo\n" +
            "    - kotlin-stdlib-jdk7-1.4.32.jar (org.jetbrains.kotlin:kotlin-stdlib-jdk7:1.4.32) from repository MavenRepo\n" +
            "    - kotlin-stdlib-jdk7-1.4.32.pom (org.jetbrains.kotlin:kotlin-stdlib-jdk7:1.4.32) from repository MavenRepo\n" +
            "    - kotlin-stdlib-jdk8-1.4.32.jar (org.jetbrains.kotlin:kotlin-stdlib-jdk8:1.4.32) from repository MavenRepo\n" +
            "    - kotlin-stdlib-jdk8-1.4.32.pom (org.jetbrains.kotlin:kotlin-stdlib-jdk8:1.4.32) from repository MavenRepo\n" +
            "    - kotlinx-coroutines-core-1.4.1.module (org.jetbrains.kotlinx:kotlinx-coroutines-core:1.4.1) from repository MavenRepo\n" +
            "    - kotlinx-coroutines-core-jvm-1.4.1.jar (org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.4.1) from repository MavenRepo\n" +
            "    - kotlinx-coroutines-core-jvm-1.4.1.module (org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.4.1) from repository MavenRepo\n" +
            "    - kxml2-2.3.0.jar (net.sf.kxml:kxml2:2.3.0) from repository MavenRepo\n" +
            "    - kxml2-2.3.0.pom (net.sf.kxml:kxml2:2.3.0) from repository MavenRepo\n" +
            "    - layoutlib-api-30.1.0.jar (com.android.tools.layoutlib:layoutlib-api:30.1.0) from repository Google\n" +
            "    - layoutlib-api-30.1.0.module (com.android.tools.layoutlib:layoutlib-api:30.1.0) from repository Google\n" +
            "    - lint-model-30.1.0.jar (com.android.tools.lint:lint-model:30.1.0) from repository Google\n" +
            "    - lint-model-30.1.0.module (com.android.tools.lint:lint-model:30.1.0) from repository Google\n" +
            "    - listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar (com.google.guava:listenablefuture:9999.0-empty-to-avoid-conflict-with-guava) from repository MavenRepo\n" +
            "    - listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.pom (com.google.guava:listenablefuture:9999.0-empty-to-avoid-conflict-with-guava) from repository MavenRepo\n" +
            "    - manifest-merger-30.1.0.jar (com.android.tools.build:manifest-merger:30.1.0) from repository Google\n" +
            "    - manifest-merger-30.1.0.module (com.android.tools.build:manifest-merger:30.1.0) from repository Google\n" +
            "    - markdown-0.2.1.module (org.jetbrains:markdown:0.2.1) from repository MavenRepo\n" +
            "    - markdown-jvm-0.2.1.jar (org.jetbrains:markdown-jvm:0.2.1) from repository MavenRepo\n" +
            "    - markdown-jvm-0.2.1.module (org.jetbrains:markdown-jvm:0.2.1) from repository MavenRepo\n" +
            "    - mojo-parent-40.pom (org.codehaus.mojo:mojo-parent:40) from repository MavenRepo\n" +
            "    - netty-buffer-4.1.34.Final.jar (io.netty:netty-buffer:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-buffer-4.1.34.Final.pom (io.netty:netty-buffer:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-codec-4.1.34.Final.jar (io.netty:netty-codec:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-codec-4.1.34.Final.pom (io.netty:netty-codec:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-codec-http-4.1.34.Final.jar (io.netty:netty-codec-http:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-codec-http-4.1.34.Final.pom (io.netty:netty-codec-http:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-codec-http2-4.1.34.Final.jar (io.netty:netty-codec-http2:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-codec-http2-4.1.34.Final.pom (io.netty:netty-codec-http2:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-codec-socks-4.1.34.Final.jar (io.netty:netty-codec-socks:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-codec-socks-4.1.34.Final.pom (io.netty:netty-codec-socks:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-common-4.1.34.Final.jar (io.netty:netty-common:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-common-4.1.34.Final.pom (io.netty:netty-common:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-handler-4.1.34.Final.jar (io.netty:netty-handler:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-handler-4.1.34.Final.pom (io.netty:netty-handler:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-handler-proxy-4.1.34.Final.jar (io.netty:netty-handler-proxy:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-handler-proxy-4.1.34.Final.pom (io.netty:netty-handler-proxy:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-parent-4.1.34.Final.pom (io.netty:netty-parent:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-resolver-4.1.34.Final.jar (io.netty:netty-resolver:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-resolver-4.1.34.Final.pom (io.netty:netty-resolver:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-transport-4.1.34.Final.jar (io.netty:netty-transport:4.1.34.Final) from repository MavenRepo\n" +
            "    - netty-transport-4.1.34.Final.pom (io.netty:netty-transport:4.1.34.Final) from repository MavenRepo\n" +
            "    - opencensus-api-0.21.0.jar (io.opencensus:opencensus-api:0.21.0) from repository MavenRepo\n" +
            "    - opencensus-api-0.21.0.pom (io.opencensus:opencensus-api:0.21.0) from repository MavenRepo\n" +
            "    - opencensus-contrib-grpc-metrics-0.21.0.jar (io.opencensus:opencensus-contrib-grpc-metrics:0.21.0) from repository MavenRepo\n" +
            "    - opencensus-contrib-grpc-metrics-0.21.0.pom (io.opencensus:opencensus-contrib-grpc-metrics:0.21.0) from repository MavenRepo\n" +
            "    - oss-parent-38.pom (com.fasterxml:oss-parent:38) from repository MavenRepo\n" +
            "    - oss-parent-7.pom (org.sonatype.oss:oss-parent:7) from repository MavenRepo\n" +
            "    - oss-parent-9.pom (org.sonatype.oss:oss-parent:9) from repository MavenRepo\n" +
            "    - ow2-1.5.pom (org.ow2:ow2:1.5) from repository MavenRepo\n" +
            "    - project-1.0.2.pom (org.eclipse.ee4j:project:1.0.2) from repository MavenRepo\n" +
            "    - project-1.0.5.pom (org.eclipse.ee4j:project:1.0.5) from repository MavenRepo\n" +
            "    - proto-google-common-protos-1.12.0.jar (com.google.api.grpc:proto-google-common-protos:1.12.0) from repository MavenRepo\n" +
            "    - proto-google-common-protos-1.12.0.pom (com.google.api.grpc:proto-google-common-protos:1.12.0) from repository MavenRepo\n" +
            "    - protobuf-bom-3.10.0.pom (com.google.protobuf:protobuf-bom:3.10.0) from repository MavenRepo\n" +
            "    - protobuf-java-3.10.0.jar (com.google.protobuf:protobuf-java:3.10.0) from repository MavenRepo\n" +
            "    - protobuf-java-3.10.0.pom (com.google.protobuf:protobuf-java:3.10.0) from repository MavenRepo\n" +
            "    - protobuf-java-util-3.10.0.jar (com.google.protobuf:protobuf-java-util:3.10.0) from repository MavenRepo\n" +
            "    - protobuf-java-util-3.10.0.pom (com.google.protobuf:protobuf-java-util:3.10.0) from repository MavenRepo\n" +
            "    - protobuf-parent-3.10.0.pom (com.google.protobuf:protobuf-parent:3.10.0) from repository MavenRepo\n" +
            "    - protos-30.1.0.jar (com.android.tools.analytics-library:protos:30.1.0) from repository Google\n" +
            "    - protos-30.1.0.module (com.android.tools.analytics-library:protos:30.1.0) from repository Google\n" +
            "    - repository-30.1.0.jar (com.android.tools:repository:30.1.0) from repository Google\n" +
            "    - repository-30.1.0.module (com.android.tools:repository:30.1.0) from repository Google\n" +
            "    - sdk-common-30.1.0.jar (com.android.tools:sdk-common:30.1.0) from repository Google\n" +
            "    - sdk-common-30.1.0.module (com.android.tools:sdk-common:30.1.0) from repository Google\n" +
            "    - sdklib-30.1.0.jar (com.android.tools:sdklib:30.1.0) from repository Google\n" +
            "    - sdklib-30.1.0.module (com.android.tools:sdklib:30.1.0) from repository Google\n" +
            "    - shared-30.1.0.jar (com.android.tools.analytics-library:shared:30.1.0) from repository Google\n" +
            "    - shared-30.1.0.module (com.android.tools.analytics-library:shared:30.1.0) from repository Google\n" +
            "    - signflinger-7.1.0.jar (com.android:signflinger:7.1.0) from repository Google\n" +
            "    - signflinger-7.1.0.module (com.android:signflinger:7.1.0) from repository Google\n" +
            "    - slf4j-api-1.7.30.jar (org.slf4j:slf4j-api:1.7.30) from repository MavenRepo\n" +
            "    - slf4j-api-1.7.30.pom (org.slf4j:slf4j-api:1.7.30) from repository MavenRepo\n" +
            "    - slf4j-parent-1.7.30.pom (org.slf4j:slf4j-parent:1.7.30) from repository MavenRepo\n" +
            "    - stax-ex-1.8.1.jar (org.jvnet.staxex:stax-ex:1.8.1) from repository MavenRepo\n" +
            "    - stax-ex-1.8.1.pom (org.jvnet.staxex:stax-ex:1.8.1) from repository MavenRepo\n" +
            "    - stax2-api-4.2.1.jar (org.codehaus.woodstox:stax2-api:4.2.1) from repository MavenRepo\n" +
            "    - stax2-api-4.2.1.pom (org.codehaus.woodstox:stax2-api:4.2.1) from repository MavenRepo\n" +
            "    - tensorflow-lite-metadata-0.1.0-rc2.jar (org.tensorflow:tensorflow-lite-metadata:0.1.0-rc2) from repository MavenRepo\n" +
            "    - tensorflow-lite-metadata-0.1.0-rc2.pom (org.tensorflow:tensorflow-lite-metadata:0.1.0-rc2) from repository MavenRepo\n" +
            "    - tink-1.3.0-rc2.jar (com.google.crypto.tink:tink:1.3.0-rc2) from repository MavenRepo\n" +
            "    - tink-1.3.0-rc2.pom (com.google.crypto.tink:tink:1.3.0-rc2) from repository MavenRepo\n" +
            "    - tracker-30.1.0.jar (com.android.tools.analytics-library:tracker:30.1.0) from repository Google\n" +
            "    - tracker-30.1.0.module (com.android.tools.analytics-library:tracker:30.1.0) from repository Google\n" +
            "    - transform-api-2.0.0-deprecated-use-gradle-api.jar (com.android.tools.build:transform-api:2.0.0-deprecated-use-gradle-api) from repository Google\n" +
            "    - transform-api-2.0.0-deprecated-use-gradle-api.pom (com.android.tools.build:transform-api:2.0.0-deprecated-use-gradle-api) from repository Google\n" +
            "    - trove4j-1.0.20181211.jar (org.jetbrains.intellij.deps:trove4j:1.0.20181211) from repository MavenRepo\n" +
            "    - trove4j-1.0.20181211.pom (org.jetbrains.intellij.deps:trove4j:1.0.20181211) from repository MavenRepo\n" +
            "    - txw2-2.3.2.jar (org.glassfish.jaxb:txw2:2.3.2) from repository MavenRepo\n" +
            "    - txw2-2.3.2.pom (org.glassfish.jaxb:txw2:2.3.2) from repository MavenRepo\n" +
            "    - woodstox-core-6.2.1.jar (com.fasterxml.woodstox:woodstox-core:6.2.1) from repository MavenRepo\n" +
            "    - woodstox-core-6.2.1.pom (com.fasterxml.woodstox:woodstox-core:6.2.1) from repository MavenRepo\n" +
            "    - xercesImpl-2.12.0.jar (xerces:xercesImpl:2.12.0) from repository MavenRepo\n" +
            "    - xercesImpl-2.12.0.pom (xerces:xercesImpl:2.12.0) from repository MavenRepo\n" +
            "    - xml-apis-1.4.01.jar (xml-apis:xml-apis:1.4.01) from repository MavenRepo\n" +
            "    - xml-apis-1.4.01.pom (xml-apis:xml-apis:1.4.01) from repository MavenRepo\n" +
            "    - zipflinger-7.1.0.jar (com.android:zipflinger:7.1.0) from repository Google\n" +
            "    - zipflinger-7.1.0.module (com.android:zipflinger:7.1.0) from repository Google";

    private static final String ERRS_4 =
            "    - gson-2.8.9.jar (com.google.code.gson:gson:2.8.9) from repository MavenRepo\n" +
            "    - gson-2.8.9.pom (com.google.code.gson:gson:2.8.9) from repository MavenRepo\n" +
            "    - gson-parent-2.8.9.pom (com.google.code.gson:gson-parent:2.8.9) from repository MavenRepo\n" +
            "    - oss-parent-7.pom (org.sonatype.oss:oss-parent:7) from repository MavenRepo";

    private static final String ERRS_5 =
            "    - apache-13.pom (org.apache:apache:13) from repository MavenRepo\n" +
            "    - apache-23.pom (org.apache:apache:23) from repository MavenRepo\n" +
            "    - bcprov-jdk15on-1.70.jar (org.bouncycastle:bcprov-jdk15on:1.70) from repository MavenRepo\n" +
            "    - bcprov-jdk15on-1.70.pom (org.bouncycastle:bcprov-jdk15on:1.70) from repository MavenRepo\n" +
            "    - commons-codec-1.15.jar (commons-codec:commons-codec:1.15) from repository MavenRepo\n" +
            "    - commons-codec-1.15.pom (commons-codec:commons-codec:1.15) from repository MavenRepo\n" +
            "    - commons-math3-3.2.jar (org.apache.commons:commons-math3:3.2) from repository MavenRepo\n" +
            "    - commons-math3-3.2.pom (org.apache.commons:commons-math3:3.2) from repository MavenRepo\n" +
            "    - commons-parent-28.pom (org.apache.commons:commons-parent:28) from repository MavenRepo\n" +
            "    - commons-parent-52.pom (org.apache.commons:commons-parent:52) from repository MavenRepo\n" +
            "    - jmh-core-1.34.jar (org.openjdk.jmh:jmh-core:1.34) from repository MavenRepo\n" +
            "    - jmh-core-1.34.pom (org.openjdk.jmh:jmh-core:1.34) from repository MavenRepo\n" +
            "    - jmh-parent-1.34.pom (org.openjdk.jmh:jmh-parent:1.34) from repository MavenRepo\n" +
            "    - jopt-simple-5.0.4.jar (net.sf.jopt-simple:jopt-simple:5.0.4) from repository MavenRepo\n" +
            "    - jopt-simple-5.0.4.pom (net.sf.jopt-simple:jopt-simple:5.0.4) from repository MavenRepo";

    private static final String ERRS_6 =
            "    - jmh-generator-annprocess-1.34.jar (org.openjdk.jmh:jmh-generator-annprocess:1.34) from repository MavenRepo\n" +
            "    - jmh-generator-annprocess-1.34.pom (org.openjdk.jmh:jmh-generator-annprocess:1.34) from repository MavenRepo";

    private static final String ERRS_7 =
            "    - apiguardian-api-1.1.2.jar (org.apiguardian:apiguardian-api:1.1.2) from repository MavenRepo\n" +
            "    - apiguardian-api-1.1.2.module (org.apiguardian:apiguardian-api:1.1.2) from repository MavenRepo\n" +
            "    - junit-bom-5.8.2.module (org.junit:junit-bom:5.8.2) from repository MavenRepo\n" +
            "    - junit-jupiter-api-5.8.2.jar (org.junit.jupiter:junit-jupiter-api:5.8.2) from repository MavenRepo\n" +
            "    - junit-jupiter-api-5.8.2.module (org.junit.jupiter:junit-jupiter-api:5.8.2) from repository MavenRepo\n" +
            "    - junit-platform-commons-1.8.2.jar (org.junit.platform:junit-platform-commons:1.8.2) from repository MavenRepo\n" +
            "    - junit-platform-commons-1.8.2.module (org.junit.platform:junit-platform-commons:1.8.2) from repository MavenRepo\n" +
            "    - opentest4j-1.2.0.jar (org.opentest4j:opentest4j:1.2.0) from repository MavenRepo\n" +
            "    - opentest4j-1.2.0.pom (org.opentest4j:opentest4j:1.2.0) from repository MavenRepo";

    private static final String ERRS_8 =
            "    - junit-jupiter-engine-5.8.2.jar (org.junit.jupiter:junit-jupiter-engine:5.8.2) from repository MavenRepo\n" +
            "    - junit-jupiter-engine-5.8.2.module (org.junit.jupiter:junit-jupiter-engine:5.8.2) from repository MavenRepo\n" +
            "    - junit-platform-engine-1.8.2.jar (org.junit.platform:junit-platform-engine:1.8.2) from repository MavenRepo\n" +
            "    - junit-platform-engine-1.8.2.module (org.junit.platform:junit-platform-engine:1.8.2) from repository MavenRepo";

    private static final String ERRS_9 =
            "  - commons-math3-3.2.jar (org.apache.commons:commons-math3:3.2) from repository MavenRepo\n" +
            "  - jmh-core-1.34.jar (org.openjdk.jmh:jmh-core:1.34) from repository MavenRepo\n" +
            "  - jmh-generator-annprocess-1.34.jar (org.openjdk.jmh:jmh-generator-annprocess:1.34) from repository MavenRepo\n" +
            "  - jopt-simple-5.0.4.jar (net.sf.jopt-simple:jopt-simple:5.0.4) from repository MavenRepo\n" +
            "  - bcprov-ext-jdk15on-1.70.jar (org.bouncycastle:bcprov-ext-jdk15on:1.70) from repository MavenRepo\n" +
            "  - commons-codec-1.15.jar (commons-codec:commons-codec:1.15) from repository MavenRepo\n" +
            "  - bcprov-ext-jdk15on-1.70-sources.jar (org.bouncycastle:bcprov-ext-jdk15on:1.70) from repository MavenRepo\n" +
            "  - commons-codec-1.15-sources.jar (commons-codec:commons-codec:1.15) from repository MavenRepo\n" +
            "  - commons-math3-3.2-sources.jar (org.apache.commons:commons-math3:3.2) from repository MavenRepo\n" +
            "  - jmh-core-1.34-sources.jar (org.openjdk.jmh:jmh-core:1.34) from repository MavenRepo\n" +
            "  - jopt-simple-5.0.4-sources.jar (net.sf.jopt-simple:jopt-simple:5.0.4) from repository MavenRepo";

    private static final String ERRS_10 = "  - apache-13.pom (org.apache:apache:13) from repository MavenRepo\n" +
            "  - apache-23.pom (org.apache:apache:23) from repository MavenRepo\n" +
            "  - apiguardian-api-1.1.2.module (org.apiguardian:apiguardian-api:1.1.2) from repository MavenRepo\n" +
            "  - bcprov-jdk15on-1.70.pom (org.bouncycastle:bcprov-jdk15on:1.70) from repository MavenRepo\n" +
            "  - commons-codec-1.15.pom (commons-codec:commons-codec:1.15) from repository MavenRepo\n" +
            "  - commons-math3-3.2.jar (org.apache.commons:commons-math3:3.2) from repository MavenRepo\n" +
            "  - commons-math3-3.2.pom (org.apache.commons:commons-math3:3.2) from repository MavenRepo\n" +
            "  - commons-parent-28.pom (org.apache.commons:commons-parent:28) from repository MavenRepo\n" +
            "  - commons-parent-52.pom (org.apache.commons:commons-parent:52) from repository MavenRepo\n" +
            "  - gson-2.8.9.pom (com.google.code.gson:gson:2.8.9) from repository MavenRepo\n" +
            "  - gson-parent-2.8.9.pom (com.google.code.gson:gson-parent:2.8.9) from repository MavenRepo\n" +
            "  - jmh-core-1.34.jar (org.openjdk.jmh:jmh-core:1.34) from repository MavenRepo\n" +
            "  - jmh-core-1.34.pom (org.openjdk.jmh:jmh-core:1.34) from repository MavenRepo\n" +
            "  - jmh-generator-annprocess-1.34.jar (org.openjdk.jmh:jmh-generator-annprocess:1.34) from repository MavenRepo\n" +
            "  - jmh-generator-annprocess-1.34.pom (org.openjdk.jmh:jmh-generator-annprocess:1.34) from repository MavenRepo\n" +
            "  - jmh-parent-1.34.pom (org.openjdk.jmh:jmh-parent:1.34) from repository MavenRepo\n" +
            "  - jopt-simple-5.0.4.jar (net.sf.jopt-simple:jopt-simple:5.0.4) from repository MavenRepo\n" +
            "  - jopt-simple-5.0.4.pom (net.sf.jopt-simple:jopt-simple:5.0.4) from repository MavenRepo\n" +
            "  - junit-bom-5.8.2.module (org.junit:junit-bom:5.8.2) from repository MavenRepo\n" +
            "  - junit-jupiter-api-5.8.2.module (org.junit.jupiter:junit-jupiter-api:5.8.2) from repository MavenRepo\n" +
            "  - junit-jupiter-engine-5.8.2.module (org.junit.jupiter:junit-jupiter-engine:5.8.2) from repository MavenRepo\n" +
            "  - junit-platform-commons-1.8.2.module (org.junit.platform:junit-platform-commons:1.8.2) from repository MavenRepo\n" +
            "  - junit-platform-engine-1.8.2.module (org.junit.platform:junit-platform-engine:1.8.2) from repository MavenRepo\n" +
            "  - opentest4j-1.2.0.pom (org.opentest4j:opentest4j:1.2.0) from repository MavenRepo\n" +
            "  - oss-parent-7.pom (org.sonatype.oss:oss-parent:7) from repository MavenRepo\n" +
            "  - bcprov-jdk15on-1.70.jar (org.bouncycastle:bcprov-jdk15on:1.70) from repository MavenRepo\n" +
            "  - commons-codec-1.15.jar (commons-codec:commons-codec:1.15) from repository MavenRepo\n" +
            "  - bcprov-jdk15on-1.70-sources.jar (org.bouncycastle:bcprov-jdk15on:1.70) from repository MavenRepo\n" +
            "  - commons-codec-1.15-sources.jar (commons-codec:commons-codec:1.15) from repository MavenRepo\n" +
            "  - commons-math3-3.2-sources.jar (org.apache.commons:commons-math3:3.2) from repository MavenRepo\n" +
            "  - jmh-core-1.34-sources.jar (org.openjdk.jmh:jmh-core:1.34) from repository MavenRepo\n" +
            "  - jopt-simple-5.0.4-sources.jar (net.sf.jopt-simple:jopt-simple:5.0.4) from repository MavenRepo";

    private static final String ERRS_11 = "  - gson-2.8.9.jar (com.google.code.gson:gson:2.8.9) from repository MavenRepo\n" +
            "  - gson-2.8.9-sources.jar (com.google.code.gson:gson:2.8.9) from repository MavenRepo";

    private static final String ERRS_12 = "  - apiguardian-api-1.1.2.jar (org.apiguardian:apiguardian-api:1.1.2) from repository MavenRepo\n" +
            "  - junit-jupiter-api-5.8.2.jar (org.junit.jupiter:junit-jupiter-api:5.8.2) from repository MavenRepo\n" +
            "  - junit-platform-commons-1.8.2.jar (org.junit.platform:junit-platform-commons:1.8.2) from repository MavenRepo\n" +
            "  - opentest4j-1.2.0.jar (org.opentest4j:opentest4j:1.2.0) from repository MavenRepo\n" +
            "  - apiguardian-api-1.1.2-sources.jar (org.apiguardian:apiguardian-api:1.1.2) from repository MavenRepo\n" +
            "  - junit-jupiter-api-5.8.2-sources.jar (org.junit.jupiter:junit-jupiter-api:5.8.2) from repository MavenRepo\n" +
            "  - junit-platform-commons-1.8.2-sources.jar (org.junit.platform:junit-platform-commons:1.8.2) from repository MavenRepo\n" +
            "  - opentest4j-1.2.0-sources.jar (org.opentest4j:opentest4j:1.2.0) from repository MavenRepo";

    private static final String ERRS_13 = "  - junit-jupiter-engine-5.8.2-sources.jar (org.junit.jupiter:junit-jupiter-engine:5.8.2) from repository MavenRepo\n" +
            "  - junit-platform-engine-1.8.2-sources.jar (org.junit.platform:junit-platform-engine:1.8.2) from repository MavenRepo";

    private static final String ONE = "  - jmh-core-1.29-sources.jar (org.openjdk.jmh:jmh-core:1.29) from repository Gradle Central Plugin Repository\n" +
            "  - jopt-simple-4.6-sources.jar (net.sf.jopt-simple:jopt-simple:4.6) from repository Gradle Central Plugin Repository\n" +
            "  - asm-9.0.module (org.ow2.asm:asm:9.0) from repository MavenRepo\n" +
            "  - jmh-generator-asm-1.29.pom (org.openjdk.jmh:jmh-generator-asm:1.29) from repository MavenRepo\n" +
            "  - jmh-generator-bytecode-1.29.pom (org.openjdk.jmh:jmh-generator-bytecode:1.29) from repository MavenRepo\n" +
            "  - jmh-generator-reflection-1.29.pom (org.openjdk.jmh:jmh-generator-reflection:1.29) from repository MavenRepo\n" +
            "  - asm-9.0.jar (org.ow2.asm:asm:9.0) from repository MavenRepo\n" +
            "  - jmh-generator-asm-1.29.jar (org.openjdk.jmh:jmh-generator-asm:1.29) from repository MavenRepo\n" +
            "  - jmh-generator-bytecode-1.29.jar (org.openjdk.jmh:jmh-generator-bytecode:1.29) from repository MavenRepo\n" +
            "  - jmh-generator-reflection-1.29.jar (org.openjdk.jmh:jmh-generator-reflection:1.29) from repository MavenRepo\n" +
            "  - asm-9.0-sources.jar (org.ow2.asm:asm:9.0) from repository MavenRepo\n" +
            "  - jmh-core-1.29-sources.jar (org.openjdk.jmh:jmh-core:1.29) from repository MavenRepo\n" +
            "  - jmh-generator-asm-1.29-sources.jar (org.openjdk.jmh:jmh-generator-asm:1.29) from repository MavenRepo\n" +
            "  - jmh-generator-bytecode-1.29-sources.jar (org.openjdk.jmh:jmh-generator-bytecode:1.29) from repository MavenRepo\n" +
            "  - jmh-generator-reflection-1.29-sources.jar (org.openjdk.jmh:jmh-generator-reflection:1.29) from repository MavenRepo\n" +
            "  - jopt-simple-4.6-sources.jar (net.sf.jopt-simple:jopt-simple:4.6) from repository MavenRepo";

    private static final String MAVEN_CENTRAL_URL = "https://repo.maven.apache.org/maven2/";
    private static final String GOOGLE_URL = "https://dl.google.com/dl/android/maven2/";
    private static final String GRADLE_URL = "https://plugins.gradle.org/m2/";

    private static final String MAVEN_ORIGIN = MAVEN_CENTRAL_URL.replace("https://", "");
    private static final String GOOGLE_ORIGIN = GOOGLE_URL.replace("https://", "");
    private static final String GRADLE_ORIGIN = GRADLE_URL.replace("https://", "");

    private static final int DIGEST_LEN_BITS = 256;
    private static final int DIGEST_LEN_BYTES = DIGEST_LEN_BITS / Byte.SIZE;
    private static final int DIGEST_HEX_CHARS = DIGEST_LEN_BITS / FastHex.BITS_PER_CHAR;
    private static final String DIGEST_ALGORITHM = "SHA-" + DIGEST_LEN_BITS;

    public static void main(String[] args0) throws IOException, NoSuchAlgorithmException {
        final ConcurrentHashMap<String, Component> components = new ConcurrentHashMap<>(128);
        try (BufferedReader br = new BufferedReader(new StringReader(ONE))) {
            final MessageDigest sha256 = newMessageDigest();
            String line;
            while((line = br.readLine()) != null) {
                if(line.indexOf(") from repository MavenRepo") > 0) {
                    addArtifact(line, MAVEN_CENTRAL_URL, sha256, MAVEN_ORIGIN, components);
                } else if(line.indexOf(") from repository MavenLocal") > 0) {
                    addArtifact(line, MAVEN_CENTRAL_URL, sha256, MAVEN_ORIGIN, components);
                } else if(line.indexOf(") from repository Google") > 0) {
                    addArtifact(line, GOOGLE_URL, sha256, GOOGLE_ORIGIN, components);
                } else if(line.indexOf(") from repository Gradle Central Plugin Repository") > 0) {
                    addArtifact(line, GRADLE_URL, sha256, GRADLE_ORIGIN, components);
                } else {
                    System.err.println("skipping " + line);
                }
            }
        }
        final StringBuilder sb = new StringBuilder();
        components.values()
                .forEach(c -> sb.append(c.toString()));
        System.out.println(sb);
    }

    private static MessageDigest newMessageDigest() throws NoSuchAlgorithmException {
        final MessageDigest md = MessageDigest.getInstance(DIGEST_ALGORITHM);
        final int len = md.getDigestLength();
        if (len * FastHex.CHARS_PER_BYTE != DIGEST_HEX_CHARS) throw new Error("bad constants: " + FastHex.CHARS_PER_BYTE + " and " + DIGEST_HEX_CHARS);
        if (len != DIGEST_LEN_BYTES) throw new Error("bad init: " + len + " != " + DIGEST_LEN_BYTES);
        return md;
    }

    private static void addArtifact(String line, String repoUrl, MessageDigest md, String origin, Map<String, Component> components) throws IOException {
        final String[] parts = line.split("- |:| \\(|\\) ");
        final int start = parts.length - 5;
        final String artifactName = parts[start];
        final String group = parts[start+1];
        final String name = parts[start+2];
        final String version = parts[start+3];
        final String artifactUrl = repoUrl + group.replace('.', '/') + '/' + name + '/' + version + '/' + artifactName;
        final String componentKey = group + ':' + name + ':' + version;
        components.computeIfAbsent(componentKey, key -> new Component(group, name, version, new ArrayList<>()))
                .artifacts.add(new Artifact(artifactName, getHash(artifactUrl, md), origin));
    }

    private static String getHash(final String artifactUrl, final MessageDigest md) throws IOException {
        final HttpsURLConnection conn = (HttpsURLConnection) new URL(artifactUrl + ".sha256").openConnection();
        conn.setConnectTimeout(300);
        conn.setReadTimeout(250);
        boolean hashNotFound = false;
        try (BufferedInputStream bis = new BufferedInputStream(conn.getInputStream())) {
            return readHash(bis);
        } catch (FileNotFoundException fnfe) {
            if (conn.getResponseCode() == 404) {
                hashNotFound = true;
                return downloadAndHash(artifactUrl, md);
            }
            throw fnfe;
        } finally {
            conn.disconnect();
            System.out.println((hashNotFound ? "HASHED\t\t" : "FOUND HASH\t") + artifactUrl);
        }
    }

    private static String readHash(InputStream bis) throws IOException {
        final byte[] buffer = new byte[DIGEST_HEX_CHARS];
        final int read = bis.read(buffer);
        if (read != buffer.length) throw new Error("bad read: " + read + " != " + buffer.length);
        final String hash = new String(buffer, 0, read);
        if (bis.read(buffer) != -1) throw new Error("not -1");
        return hash;
    }

    private static String downloadAndHash(final String artifactUrl, final MessageDigest md) throws IOException {
        HttpsURLConnection conn = (HttpsURLConnection) new URL(artifactUrl).openConnection();
        conn.setConnectTimeout(300);
        conn.setReadTimeout(900);
        try (BufferedInputStream bis = new BufferedInputStream(conn.getInputStream())) {
            byte[] buffer = new byte[4096];
            int read;
            while ((read = bis.read(buffer)) != -1)
                md.update(buffer, 0, read);
            return FastHex.encodeToString(md.digest());
        } finally {
            md.reset();
            conn.disconnect();
        }
    }

    private static final class Component {
        private final String group;
        private final String name;
        private final String version;
        private final List<Artifact> artifacts;

        private Component(String group, String name, String version, List<Artifact> artifacts) {
            this.group = group;
            this.name = name;
            this.version = version;
            this.artifacts = artifacts;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder("<component group=\"" + group + "\" name=\"" + name + "\" version=\"" + version + "\">\n");
            for (Artifact artifact : artifacts) {
                sb.append(artifact.toString());
            }
            return sb.append("</component>\n").toString();
        }
    }

    private static final class Artifact {
        private final String name;
        private final String hash;
        private final String origin;

        public Artifact(String name, String hash, String origin) {
            this.name = name;
            this.hash = hash;
            this.origin = origin;
        }

        @Override
        public String toString() {
            return "    <artifact name=\"" + name + "\">\n"
                 + "        <sha256 value=\"" + hash + "\" origin=\"" + origin + "\"/>\n"
                 + "    </artifact>\n";
        }
    }
}
