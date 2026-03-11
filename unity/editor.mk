include ../common.mk

ifdef UNITY_CHANGESET
$(EDITOR_DIR):
	@ $(ECHO) downloading editor...
	@ $(CURL) https://download.unity3d.com/download_unity/$(UNITY_CHANGESET)/LinuxEditorInstaller/Unity-$(UNITY_VERSION).tar.xz -o Unity.tar.xz

	@ $(ECHO) extracting editor...
	@ tar -xf Unity.tar.xz
	@ touch -m Editor

	@ rm Unity.tar.xz

ifeq "$(call VER_GTE,$(UNITY_VERSION),2019.4.0f1)" "YES"
	@ $(ECHO) downloading editor support...
	@ $(CURL) https://download.unity3d.com/download_unity/$(UNITY_CHANGESET)/LinuxEditorTargetInstaller/UnitySetup-Linux-IL2CPP-Support-for-Editor-$(UNITY_VERSION).tar.xz -o Support.tar.xz

	@ $(ECHO) extracting editor support...
	@ tar -xf Support.tar.xz
	@ touch -m Editor
	
	@ rm Support.tar.xz
endif
endif

.PHONY: editor
editor: $(EDITOR_DIR)
