object ThemidaUnpackerWnd: TThemidaUnpackerWnd
  Left = 0
  Top = 0
  Caption = 'Magicmida'
  ClientHeight = 300
  ClientWidth = 635
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OnCreate = FormCreate
  TextHeight = 13
  object btnUnpack: TButton
    Left = 0
    Top = 0
    Width = 94
    Height = 24
    Align = alLeft
    Caption = 'Unpack'
    TabOrder = 0
    OnClick = btnUnpackClick
  end
  object LV: TListView
    Left = 0
    Top = 24
    Width = 635
    Height = 276
    Align = alBottom
    Anchors = [akLeft, akTop, akRight, akBottom]
    Columns = <
      item
        AutoSize = True
      end>
    SmallImages = ImageList1
    TabOrder = 1
    ViewStyle = vsReport
    ExplicitWidth = 631
    ExplicitHeight = 275
  end
  object btnShrink: TButton
    Left = 496
    Top = 0
    Width = 139
    Height = 24
    Hint = 
      'Strips all Themida sections from the binary. Only works if absol' +
      'utely no VM references are left!'
    Align = alRight
    Caption = 'Shrink (after unvirtualizing)'
    ParentShowHint = False
    ShowHint = True
    TabOrder = 2
    OnClick = btnShrinkClick
    ExplicitLeft = 492
  end
  object btnDumpProcess: TButton
    Left = 416
    Top = 0
    Width = 80
    Height = 24
    Hint = 'For dumping process after using OreansUnvirtualizer'
    Align = alRight
    Caption = 'Dump process'
    ParentShowHint = False
    ShowHint = True
    TabOrder = 3
    OnClick = btnDumpProcessClick
    ExplicitLeft = 412
  end
  object cbDataSections: TCheckBox
    Left = 112
    Top = 3
    Width = 176
    Height = 17
    Hint = 
      'Attempt to split Themida merged sections. This is vital for MSVC' +
      ' applications utilizing Thread Local Storage.'
    Caption = 'Auto create data sections'
    Checked = True
    ParentShowHint = False
    PopupMenu = pmSections
    ShowHint = True
    State = cbChecked
    TabOrder = 4
  end
  object OD: TOpenDialog
    Filter = 'Application|*.exe|Nexshit|*.aes'
    Options = [ofHideReadOnly, ofFileMustExist, ofEnableSizing]
    Left = 120
    Top = 32
  end
  object ImageList1: TImageList
    Left = 200
    Top = 32
    Bitmap = {
      494C010103000800040010001000FFFFFFFFFF10FFFFFFFFFFFFFFFF424D3600
      0000000000003600000028000000400000001000000001002000000000000010
      0000000000000000000000000000000000000000000000000000000000000000
      0000F6EAE420DBA6898FCE8155CFCC6B35FFCF7139FFD68757CFE5AE8C8FF9ED
      E520000000000000000000000000000000000000000000000000000000000000
      000000000000FBFBFB04EBEBEB14D5D5D52AD5D5D52AEAEAEA15FBFBFB040000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000FAF4F110D7A3
      888FC25F2AFFD1662BFFDA7036FFDE7C42FFE38A4FFFE89A5FFFE69D62FFDE88
      4BFFE9B18D8FFCF6F2100000000000000000000000000000000000000000FCFC
      FC03BABFBD46538973B51A885DEF08905DFE059260FE138C64EE4A8976B5B7BD
      BB48FAFAFA050000000000000000000000000000000000000000FAFBFE056B8F
      E7A16E90E69E6E90E69E6E90E69E6E90E69E6E90E69E6E90E69E6E90E69E6C8F
      E7A0D6DFF72E0000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000FAF4F110C27852CFC65B
      2AFFD26026FFD6682AFFDA7130FFDF7A37FFE4843EFFE98F46FFEF9C53FFF4B9
      79FFEEAB6CFFE2915BCFFCF6F210000000000000000000000000F7F7F7087797
      8A8F0D905AFC008F57FF00925BFF009560FF009965FF009C6BFF00A070FF04A0
      74FB71978D8EF5F5F50A0000000000000000000000005179E0C5F5F6FFFF8C94
      FFFF848CFFFF848CFFFF848CFFFF848CFFFF848CFFFF848CFFFF848CFFFF8890
      FFFFDDDEFFFF456CDEFF00000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000D3A0868FC25C2FFFCE5B
      27FFD26024FFD6682AFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF994EFFF4A5
      56FFFAC17CFFEFAD6EFFE9B18D8F0000000000000000FCFCFC0376998C900596
      5DFF00965DFF009961FF009C66FF009F6BFF00A370FF00A675FF00A97AFF00AD
      80FF01B085FE719B918EFBFBFB040000000000000000CCCFFFFF1B2AF8FF1D2A
      F1FF676ED4FF1E2FF6FF202EF7FF202EF7FF202EF7FF2230F7FF2D36D5FF1023
      E7FF1E2CF8FF747CFDFFE4EAFA1B000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000F4E9E420B85B2FFFCB5E2FFFCE58
      1EFFD15F23FFD56729FFDA702FFFFFFFFFFFFFFFFFFFE88C44FFED964BFFF19F
      52FFF5A657FFF5BB7BFFDF894CFFF9EDE52000000000BDC4C2430CA067FC009F
      64FF00A168FF06A36EFF32B188FF00A975FF00AD7BFF00B080FF00B385FF00B7
      8BFF00BA90FF04B992FBBBC2C04400000000000000000A1FF1FF0A1DEBFFC5C5
      D1FFEAE7E6FF6A6FBFFF0E20F0FF0D22F1FF0D24F1FF1523C1FFEBE8E7FFEAE7
      E3FF0013E1FF0007F0FFCED7F5AA000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000D09D868FC4673EFFCA541DFFCD57
      1DFFD05E22FFD46527FFD86D2EFFFFFFFFFFFFFFFFFFE58740FFE98F46FFED96
      4CFFEF9B4FFFF09F55FFE79F65FFE5AE8C8FFDFDFD02549A81B400A86CFF00AB
      70FF06AB74FFB3E1D2FFFCFDFDFF5DC6A8FF00B786FF00BB8BFF00BE90FF00C1
      95FF00C49AFF00C79FFF4DA090B2FCFCFC03FBFBFE0A0000EEFF535ACFFFE7E4
      E1FFE6E4E1FFE6E4E1FF5E64BCFF0115EEFF0A1DC0FFE9E6E1FFE6E4E1FFE6E4
      E1FFB5B5D0FF0000EEFFD1DAF6AE000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000BA714FCFD07951FFCA511AFFCC55
      1CFFCF5B20FFD36225FFD76A2BFFFFFFFFFFFFFFFFFFE2803CFFE58741FFE88D
      45FFEA9047FFEA9148FFE99D62FFD68757CFF2F2F20D16AF7AF300B478FF06B4
      7CFFB3E3D4FFD8F1EAFF6BCFB3FFF8FCFBFF5DCEB2FF00C496FF00C89BFF00CB
      A0FF00CDA4FF00D0A9FF14C1A2EDEEEEEE11FBFBFE0A0000F5FF0012F5FF5662
      BCFFE3DFDDFFE3DFDDFFE4DFDDFF6870B0FFE5E2DDFFE3DFDDFFE3DFDDFFB2B1
      C7FF000EF0FF0000F5FFD1DAF4AE000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000B56039FFD37D56FFCF622EFFCC56
      1DFFCE581EFFD15F23FFD46528FFFFFFFFFFFFFFFFFFDE7936FFE17F3AFFE383
      3EFFE5853FFFE58640FFE48D51FFD0723AFFDADCDB250DC287FF00C184FF2BC6
      97FFC6EDE2FF19C696FF00C893FF56D3B4FFF8FCFBFF5DD6BBFF01D1A5FF04D5
      ABFF04D7B0FF03D9B3FF06DBB8FEDCDDDC23FBFCFE0A0000FFFF000CFFFF0008
      FFFF5761C2FFE0DCD8FFE0DCD8FFE0DCD8FFE0DCD8FFE0DCD8FFAFAFC5FF0002
      FCFF000CFFFF0000FFFFD1DAF4AE000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000B5613BFFD5825CFFD06634FFD166
      32FFD06028FFCF5C22FFD26124FFFFFFFFFFFFFFFFFFDB7131FFDD7634FFDE7A
      37FFDF7C38FFE07C38FFDF7F45FFCC6C36FFDADDDC251ED09AFF18D09AFF0ED0
      99FF06CE98FF01D19CFF01D3A0FF08D5A5FF63DCC2FFF8FDFCFF6BDEC8FF1ADF
      BAFF1BE2BFFF1BE3C2FF1EE5C6FEDDDEDE22FBFCFE0A0000FFFF0000FFFF0000
      FFFF0000FFFF6970B5FFDEDAD6FFDEDAD6FFDEDAD6FFB6B4C2FF0000FFFF0000
      FFFF0000FFFF0000FFFFD1DAF4AE000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000B76F4ECFD98D6BFFD06534FFD166
      34FFD26834FFD36934FFFFFFFFFFFFFFFFFFFFFFFFFFD76A2BFFD96E2EFFDA71
      30FFDB7231FFDB7232FFDA7239FFCE8155CFF4F4F40B36D4A6F436DFB0FF36E0
      B3FF36E1B6FF36E3B9FF36E4BCFF36E5BFFF35E5C1FF79E5D0FFF9FDFCFF7AE5
      D3FF35EACCFF36ECD0FF3CD9C2EEF1F1F10EFBFBFE0A6072FFFF6A7BFFFF6B7C
      FFFF5866CEFFF0EDEEFFEFECEEFFEFECEEFFEFECEEFFF0EDEEFF838AC7FF6A7A
      FFFF6A7BFFFF6476FFFFCFD8F4AE000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000CC9B858FD58E6FFFD16B3DFFD066
      34FFD16734FFD26834FFD36B35FFD56D36FFD66F37FFD77036FFD87136FFD972
      37FFDA7337FFDA7438FFD36F36FFDBA6898FFEFEFE0169BAA4B455EBC3FF55EB
      C5FF55ECC8FF55EDCAFF55EECDFF55EFCFFF55F0D1FF54EFD2FF8CEADAFFFAFD
      FDFF70ECD9FF55F3DCFF6FB7ADAFFDFDFD02FBFBFE0A5A71FFFF667BFFFF5565
      D3FFF2F1F1FFF2F0F0FFF2F0F0FFD7D7DEFFF2F0F0FFF2F0F0FFF2F0F0FF8189
      CAFF6579FFFF6075FFFFCFD8F4AE000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000F3E8E320B86744FFDB8F6DFFD065
      34FFD06634FFD16734FFD26834FFFCF6F2FFFCF6F3FFD56E37FFD66F37FFD770
      38FFD87138FFD87138FFC46430FFF6EAE42000000000C2CFCC3F70F1D1FD75F4
      D5FF75F4D7FF75F5D9FF75F5DBFF75F6DDFF75F6DEFF75F7E0FF74F6E0FF8AF0
      E0FF74F4E1FF74F4E2FBC4CDCC3D00000000F9FAFE0B516BFFFF4F67F2FFF5F4
      F3FFF3F2F2FFF3F2F2FFCACCDCFF5870FEFF828BCCFFF3F2F2FFF3F2F2FFF3F2
      F2FF7F8CE1FF576FFFFFCED7F4AF000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000CB9A848FCB8261FFD988
      63FFD06534FFD06634FFD16634FFFCF6F2FFFCF6F2FFD36A35FFD46B36FFD46C
      36FFD56D38FFCA6633FFD7A3888F0000000000000000FEFEFE018EBEB38D93F9
      E2FF94FAE4FF94FAE5FF94FAE6FF94FAE7FF94FAE8FF94FBEAFF94FBEBFF94FB
      ECFF93FBEDFF93B8B387FEFEFE0100000000000000004A67FFFF516EFFFF7A85
      CEFFF5F4F4FFC2C4DAFF4E6AFFFF526FFFFF526DFFFF7A85CEFFF5F4F4FFCACC
      DDFF4D6BFFFF4967FFFFE1E8F992000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000F9F3F110B56D4ECFCB82
      61FFDB8F6CFFD16B3DFFD06634FFD37041FFD47041FFD26834FFD26A37FFD26D
      40FFC76438FFC27852CFFAF4F110000000000000000000000000FCFCFC0396C0
      B78DA9FBEAFDAFFDEEFFAFFDEEFFAFFDEFFFAFFDF0FFAFFDF1FFAFFDF1FFA7FA
      EEFC96BBB587FBFBFB04000000000000000000000000B3BFFFFF4666FFFF4868
      FFFF6F82E7FF4564FFFF4767FFFF4767FFFF4767FFFF4868FFFF6C7FE6FF4363
      FFFF4767FFFF6D87FFFF00000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000F9F3F110CB9A
      848FB86743FFD48E6EFFD98C6AFFD5815BFFD27C54FFD17B54FFC87049FFBA5F
      34FFD3A0868FFAF4F11000000000000000000000000000000000000000000000
      0000CAD4D23D9BC7BFB2A6F3E6F4BBFEF3FFBBFEF4FFA4F1E6F296C4BDAFC9D2
      D13BFEFEFE0100000000000000000000000000000000FFFFFF0AC7D1FFFF5673
      FFFF2B54FFFF2B54FFFF2B54FFFF2B54FFFF2B54FFFF2B54FFFF2B54FFFF486A
      FFFFA6B4FFFFFFFFFF4D00000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000F3E8E320CC9B858FB76F4ECFB5603AFFB45F38FFBA714FCFD09D868FF4E9
      E420000000000000000000000000000000000000000000000000000000000000
      00000000000000000000F7F7F708DEE3E221DEE3E221F7F7F708000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000424D3E000000000000003E000000
      2800000040000000100000000100010000000000800000000000000000000000
      000000000000000000000000FFFFFF00F00FF81FFFFF0000C003E007C0070000
      8001C00380030000800180018001000000008001800100000000000000010000
      0000000000010000000000000001000000000000000100000000000000010000
      0000000000010000000080010001000080018001800100008001C00380030000
      C003F00780030000F00FFC3FFFFF000000000000000000000000000000000000
      000000000000}
  end
  object pmSections: TPopupMenu
    Left = 291
    Top = 33
    object miCreateSectionsNow: TMenuItem
      Caption = 'Create now'
      OnClick = miCreateSectionsNowClick
    end
  end
end
